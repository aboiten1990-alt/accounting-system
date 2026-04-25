import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcryptjs";
import pkg from "pg";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pkg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const port = 5000;

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json());

const PgSession = connectPgSimple(session);
app.use(
  session({
    store: new PgSession({ pool, tableName: "user_sessions" }),
    secret: process.env.SESSION_SECRET || "tourism-dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      httpOnly: true,
    },
  })
);

// ---------- Roles & permissions ----------
const ROLES = ["admin", "company_user", "employee", "accountant"];
const DEPARTMENTS = ["flights", "visas", "umrah_hajj", "medical_govt", "hotels"];

// Operation types that belong to each department
const SERVICE_TYPES_BY_DEPT = {
  flights: ["flight"],
  visas: ["visa_tourist", "visa_family", "visa_business"],
  umrah_hajj: ["umrah", "hajj"],
  medical_govt: ["medical_service", "government_service"],
  hotels: ["hotel"],
};

// Permission helpers — these mirror the UI but are enforced here regardless of UI state
function canModifyClients(user) {
  // accountant cannot create/edit/delete clients
  return ["admin", "company_user", "employee"].includes(user.role);
}
function canViewFinance(user) {
  // employees do not have access to the Payments/Finance section
  return ["admin", "company_user", "accountant"].includes(user.role);
}
function isEmployee(user) {
  return user.role === "employee";
}
function employeeCanTouchType(user, operationType) {
  if (user.role !== "employee") return true;
  if (!user.department) return false;
  const allowed = SERVICE_TYPES_BY_DEPT[user.department] || [];
  return allowed.includes(operationType);
}
function canCreateOperation(user, operationType) {
  if (user.role === "accountant") return false; // accountant cannot create new operations
  if (user.role === "employee") return employeeCanTouchType(user, operationType);
  return true; // admin, company_user
}
function canModifyOperation(user, operationType) {
  if (user.role === "employee") return employeeCanTouchType(user, operationType);
  return true; // admin, company_user, accountant
}

// ---------- Auth middleware ----------
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "غير مصرح" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "غير مصرح" });
  if (req.session.user.role !== "admin")
    return res.status(403).json({ error: "صلاحيات المسؤول مطلوبة" });
  next();
}

// ---------- Auth routes ----------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "اسم المستخدم وكلمة المرور مطلوبان" });
  }
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.password_hash, u.role, u.department,
              u.company_id, c.name AS company_name
         FROM users u
         LEFT JOIN companies c ON c.id = u.company_id
        WHERE u.username = $1`,
      [username]
    );
    if (!rows.length) {
      return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
    }
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
    }
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      department: user.department,
      company_id: user.company_id,
      company_name: user.company_name,
    };
    res.json({ user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "غير مسجل" });
  res.json({ user: req.session.user });
});

// ---------- Admin: companies ----------
app.get("/api/companies", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.*,
              (SELECT COUNT(*) FROM users WHERE company_id = c.id)::int AS users_count,
              (SELECT COUNT(*) FROM clients WHERE company_id = c.id)::int AS clients_count,
              (SELECT COUNT(*) FROM operations WHERE company_id = c.id)::int AS operations_count
         FROM companies c
        ORDER BY c.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/companies", requireAdmin, async (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: "اسم الشركة مطلوب" });
  try {
    const { rows } = await pool.query(
      "INSERT INTO companies (name) VALUES ($1) RETURNING *",
      [name.trim()]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === "23505")
      return res.status(400).json({ error: "اسم الشركة مستخدم بالفعل" });
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/companies/:id", requireAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query("DELETE FROM companies WHERE id=$1", [
      req.params.id,
    ]);
    if (!rowCount) return res.status(404).json({ error: "الشركة غير موجودة" });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Admin: users ----------
app.get("/api/users", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.role, u.department, u.company_id, u.created_at,
              c.name AS company_name
         FROM users u
         LEFT JOIN companies c ON c.id = u.company_id
        ORDER BY u.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/users", requireAdmin, async (req, res) => {
  const { username, password, role, company_id, department } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ error: "اسم المستخدم وكلمة المرور مطلوبان" });
  if (!ROLES.includes(role))
    return res.status(400).json({ error: "الدور غير صحيح" });
  // Non-admin roles all need a company
  if (role !== "admin" && !company_id)
    return res
      .status(400)
      .json({ error: "يجب اختيار شركة لهذا المستخدم" });
  // Employees must have a valid department
  let dept = null;
  if (role === "employee") {
    if (!department || !DEPARTMENTS.includes(department))
      return res
        .status(400)
        .json({ error: "يجب اختيار قسم صحيح للموظف" });
    dept = department;
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (username, password_hash, role, company_id, department)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, role, company_id, department`,
      [
        username.trim(),
        hash,
        role,
        role === "admin" ? null : company_id,
        dept,
      ]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === "23505")
      return res.status(400).json({ error: "اسم المستخدم مستخدم بالفعل" });
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/users/:id", requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (id === req.session.user.id)
    return res.status(400).json({ error: "لا يمكنك حذف حسابك الحالي" });
  try {
    const { rowCount } = await pool.query("DELETE FROM users WHERE id=$1", [id]);
    if (!rowCount) return res.status(404).json({ error: "المستخدم غير موجود" });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Clients (scoped) ----------
app.get("/api/clients", requireAuth, async (req, res) => {
  try {
    const u = req.session.user;
    const { search } = req.query;
    const where = [];
    const params = [];
    if (u.role !== "admin") {
      params.push(u.company_id);
      where.push(`company_id = $${params.length}`);
    }
    if (search && search.trim()) {
      params.push(`%${search.trim()}%`);
      where.push(`(name ILIKE $${params.length} OR COALESCE(phone,'') ILIKE $${params.length})`);
    }
    let sql = "SELECT * FROM clients";
    if (where.length) sql += ` WHERE ${where.join(" AND ")}`;
    sql += " ORDER BY created_at DESC";
    const { rows } = await pool.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/clients", requireAuth, async (req, res) => {
  const u = req.session.user;
  if (!canModifyClients(u))
    return res
      .status(403)
      .json({ error: "ليس لديك صلاحية إضافة العملاء" });
  const {
    name,
    phone,
    email,
    passport_number,
    nationality,
    notes,
    address,
    agent_name,
    company_id,
  } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: "اسم العميل مطلوب" });

  // Determine target company: admin can specify, others use their own
  const targetCompany = u.role === "admin" ? company_id : u.company_id;
  if (!targetCompany)
    return res.status(400).json({ error: "يجب تحديد الشركة" });

  try {
    const { rows } = await pool.query(
      `INSERT INTO clients
        (name, phone, email, passport_number, nationality, notes,
         address, agent_name, company_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        name.trim(),
        phone || null,
        email || null,
        passport_number || null,
        nationality || null,
        notes || null,
        address || null,
        agent_name || null,
        targetCompany,
      ]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Helper to ensure a record belongs to the current user's company (or admin)
async function assertOwnership(table, id, user) {
  const { rows } = await pool.query(
    `SELECT company_id FROM ${table} WHERE id=$1`,
    [id]
  );
  if (!rows.length) return { ok: false, status: 404, error: "غير موجود" };
  if (user.role !== "admin" && rows[0].company_id !== user.company_id)
    return { ok: false, status: 403, error: "غير مصرح" };
  return { ok: true };
}

app.put("/api/clients/:id", requireAuth, async (req, res) => {
  const u = req.session.user;
  if (!canModifyClients(u))
    return res
      .status(403)
      .json({ error: "ليس لديك صلاحية تعديل العملاء" });
  const id = parseInt(req.params.id, 10);
  const own = await assertOwnership("clients", id, u);
  if (!own.ok) return res.status(own.status).json({ error: own.error });

  const {
    name,
    phone,
    email,
    passport_number,
    nationality,
    notes,
    address,
    agent_name,
  } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: "اسم العميل مطلوب" });
  try {
    const { rows } = await pool.query(
      `UPDATE clients
         SET name=$1, phone=$2, email=$3, passport_number=$4,
             nationality=$5, notes=$6, address=$7, agent_name=$8
       WHERE id=$9
       RETURNING *`,
      [
        name.trim(),
        phone || null,
        email || null,
        passport_number || null,
        nationality || null,
        notes || null,
        address || null,
        agent_name || null,
        id,
      ]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/clients/:id", requireAuth, async (req, res) => {
  const u = req.session.user;
  if (!canModifyClients(u))
    return res
      .status(403)
      .json({ error: "ليس لديك صلاحية حذف العملاء" });
  const id = parseInt(req.params.id, 10);
  const own = await assertOwnership("clients", id, u);
  if (!own.ok) return res.status(own.status).json({ error: own.error });
  try {
    await pool.query("DELETE FROM clients WHERE id=$1", [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Operations (scoped) ----------
app.get("/api/operations", requireAuth, async (req, res) => {
  try {
    const u = req.session.user;
    const { type, types, payment_status, date_from, date_to, search } =
      req.query;
    const where = [];
    const params = [];

    if (u.role !== "admin") {
      params.push(u.company_id);
      where.push(`o.company_id = $${params.length}`);
    }
    // Employees are scoped to their department types regardless of any client filter
    if (u.role === "employee") {
      const deptTypes = SERVICE_TYPES_BY_DEPT[u.department] || [];
      if (!deptTypes.length) {
        return res.json([]); // employee with no/invalid department sees nothing
      }
      const placeholders = deptTypes.map((t) => {
        params.push(t);
        return `$${params.length}`;
      });
      where.push(`o.operation_type IN (${placeholders.join(",")})`);
    }
    // `types` is a comma-separated list (used by service-tab views)
    if (types) {
      const list = String(types)
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      if (list.length) {
        const placeholders = list.map((t) => {
          params.push(t);
          return `$${params.length}`;
        });
        where.push(`o.operation_type IN (${placeholders.join(",")})`);
      }
    }
    if (type) {
      if (type === "visa") {
        where.push(`o.operation_type LIKE 'visa_%'`);
      } else {
        params.push(type);
        where.push(`o.operation_type = $${params.length}`);
      }
    }
    if (payment_status) {
      params.push(payment_status);
      where.push(`o.payment_status = $${params.length}`);
    }
    if (date_from) {
      params.push(date_from);
      where.push(`o.operation_date >= $${params.length}`);
    }
    if (date_to) {
      params.push(date_to);
      where.push(`o.operation_date <= $${params.length}`);
    }
    if (search && search.trim()) {
      params.push(`%${search.trim()}%`);
      where.push(
        `(c.name ILIKE $${params.length} OR COALESCE(o.description,'') ILIKE $${params.length})`
      );
    }

    let sql = `
      SELECT o.*, c.name AS client_name, comp.name AS company_name
      FROM operations o
      LEFT JOIN clients c ON c.id = o.client_id
      LEFT JOIN companies comp ON comp.id = o.company_id`;
    if (where.length) sql += ` WHERE ${where.join(" AND ")}`;
    sql += " ORDER BY o.created_at DESC";

    const { rows } = await pool.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/operations", requireAuth, async (req, res) => {
  const u = req.session.user;
  const {
    client_id,
    operation_type,
    description,
    amount,
    cost,
    payment_status,
    operation_date,
  } = req.body;

  if (!client_id || !operation_type)
    return res.status(400).json({ error: "العميل ونوع العملية مطلوبان" });

  // Role-based: accountant cannot create new operations; employee only their dept types
  if (!canCreateOperation(u, operation_type)) {
    return res
      .status(403)
      .json({ error: "ليس لديك صلاحية إضافة هذه العملية" });
  }

  // Verify the client belongs to user's company (admin gets the client's company)
  const { rows: cl } = await pool.query(
    "SELECT company_id FROM clients WHERE id=$1",
    [client_id]
  );
  if (!cl.length) return res.status(400).json({ error: "العميل غير موجود" });
  if (u.role !== "admin" && cl[0].company_id !== u.company_id)
    return res.status(403).json({ error: "العميل لا ينتمي لشركتك" });
  const targetCompany = cl[0].company_id;

  try {
    const { rows } = await pool.query(
      `INSERT INTO operations
        (client_id, operation_type, description, amount, cost, payment_status, operation_date, company_id)
       VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, CURRENT_DATE), $8)
       RETURNING *`,
      [
        client_id,
        operation_type,
        description || null,
        amount || 0,
        cost || 0,
        payment_status || "unpaid",
        operation_date || null,
        targetCompany,
      ]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/operations/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const u = req.session.user;
  const own = await assertOwnership("operations", id, u);
  if (!own.ok) return res.status(own.status).json({ error: own.error });

  const {
    client_id,
    operation_type,
    description,
    amount,
    cost,
    payment_status,
    operation_date,
  } = req.body;
  if (!client_id || !operation_type)
    return res.status(400).json({ error: "العميل ونوع العملية مطلوبان" });

  // Employees can only edit operations in their department type
  // (check both the existing record and the new requested type)
  if (u.role === "employee") {
    const { rows: existing } = await pool.query(
      "SELECT operation_type FROM operations WHERE id=$1",
      [id]
    );
    if (!existing.length)
      return res.status(404).json({ error: "العملية غير موجودة" });
    if (
      !canModifyOperation(u, existing[0].operation_type) ||
      !canModifyOperation(u, operation_type)
    ) {
      return res
        .status(403)
        .json({ error: "ليس لديك صلاحية تعديل هذه العملية" });
    }
  }

  // Validate the new client belongs to same company (or admin)
  const { rows: cl } = await pool.query(
    "SELECT company_id FROM clients WHERE id=$1",
    [client_id]
  );
  if (!cl.length) return res.status(400).json({ error: "العميل غير موجود" });
  if (u.role !== "admin" && cl[0].company_id !== u.company_id)
    return res.status(403).json({ error: "العميل لا ينتمي لشركتك" });

  try {
    const { rows } = await pool.query(
      `UPDATE operations
         SET client_id=$1, operation_type=$2, description=$3,
             amount=$4, cost=$5, payment_status=$6,
             operation_date=COALESCE($7, operation_date)
       WHERE id=$8
       RETURNING *`,
      [
        client_id,
        operation_type,
        description || null,
        amount || 0,
        cost || 0,
        payment_status || "unpaid",
        operation_date || null,
        id,
      ]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/operations/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const u = req.session.user;
  const own = await assertOwnership("operations", id, u);
  if (!own.ok) return res.status(own.status).json({ error: own.error });

  // Employees can only delete operations of their department type
  if (u.role === "employee") {
    const { rows: existing } = await pool.query(
      "SELECT operation_type FROM operations WHERE id=$1",
      [id]
    );
    if (!existing.length)
      return res.status(404).json({ error: "العملية غير موجودة" });
    if (!canModifyOperation(u, existing[0].operation_type)) {
      return res
        .status(403)
        .json({ error: "ليس لديك صلاحية حذف هذه العملية" });
    }
  }
  try {
    await pool.query("DELETE FROM operations WHERE id=$1", [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Summary (scoped) ----------
app.get("/api/summary", requireAuth, async (req, res) => {
  try {
    const u = req.session.user;

    // Operations scope: company + (for employees) department types
    const opWhere = [];
    const opParams = [];
    if (u.role !== "admin") {
      opParams.push(u.company_id);
      opWhere.push(`company_id = $${opParams.length}`);
    }
    if (u.role === "employee") {
      const types = SERVICE_TYPES_BY_DEPT[u.department] || [];
      if (!types.length) {
        return res.json({
          clients_count: 0,
          operations_count: 0,
          total_income: 0,
          total_expenses: 0,
          net_profit: 0,
          total_due: 0,
        });
      }
      const ph = types.map((t) => {
        opParams.push(t);
        return `$${opParams.length}`;
      });
      opWhere.push(`operation_type IN (${ph.join(",")})`);
    }
    const opScope = opWhere.length ? `WHERE ${opWhere.join(" AND ")}` : "";

    // Clients scope: company only (department doesn't apply to clients)
    const clientScope = u.role !== "admin" ? "WHERE company_id = $1" : "";
    const clientParams = u.role !== "admin" ? [u.company_id] : [];

    const totals = await pool.query(
      `SELECT
         COUNT(*)::int AS operations_count,
         COALESCE(SUM(amount), 0)::float AS total_income,
         COALESCE(SUM(cost), 0)::float AS total_expenses,
         COALESCE(SUM(amount) - SUM(cost), 0)::float AS net_profit,
         COALESCE(SUM(amount) FILTER (WHERE payment_status <> 'paid'), 0)::float AS total_due
       FROM operations ${opScope}`,
      opParams
    );
    const clientsCount = await pool.query(
      `SELECT COUNT(*)::int AS count FROM clients ${clientScope}`,
      clientParams
    );
    res.json({
      clients_count: clientsCount.rows[0].count,
      ...totals.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Static files (must come AFTER API routes) ----------
app.use(express.static(path.join(__dirname, "public")));

app.listen(port, "0.0.0.0", () => {
  console.log(`Tourism management server running on port ${port}`);
});
