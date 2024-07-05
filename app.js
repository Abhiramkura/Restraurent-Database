const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const dbPath = path.join(__dirname, "customer.db");
const app = express();

app.use(cors());
app.use(express.json());

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3008, () => {
      console.log("Server Running at http://localhost:3008/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

//MIDDLEWARE

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401).json({ error_msg: "Invalid JWT Token" });
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
      if (error) {
        response.status(401).json({ error_msg: "Invalid JWT Token" });
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};

// API to get food menu
app.get("/food", async (request, response) => {
  try {
    const getFoodQuery = `SELECT * FROM food_menu;`;
    const foodArray = await db.all(getFoodQuery);
    response.status(200).json(foodArray);
  } catch (error) {
    console.error("Error fetching food menu:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

// API to verify login credentials and generate JWT token
app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  console.log("Username:", username);
  console.log("Password:", password);
  const selectUserQuery = `
    SELECT *
    FROM customer_credentials
    WHERE customername = ?;`;

  try {
    const dbUser = await db.get(selectUserQuery, [username]);

    console.log("Database User:", dbUser);
    if (dbUser === undefined) {
      return response
        .status(401)
        .json({ error_msg: "Invalid username or password" });
    }

    const isPasswordMatch = await bcrypt.compare(
      password,
      dbUser.customerpassword
    );

    console.log("Password Match:", isPasswordMatch);

    if (!isPasswordMatch) {
      console.log("Invalid password");
      return response
        .status(401)
        .json({ error_msg: "Invalid username or password" });
    }

    const payload = { username };
    const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");

    response.status(200).json({ jwtToken });
  } catch (error) {
    console.error("Error verifying credentials:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

// API to place order
app.post("/order", authenticateToken, async (request, response) => {
  const { customerName, orderDetails } = request.body;

  try {
    // Construct the SQL query to insert orders
    const insertOrderQuery = `
      INSERT INTO orders (customer_name, food_name, food_id, category, cost_INR, quantity, quantity_cost, chef_name)
      VALUES ${orderDetails
        .map(
          (order) =>
            `('${customerName}', '${order.foodName}', '${order.foodId}', '${
              order.category
            }', ${order.costINR}, ${order.quantity}, ${
              order.quantity * order.costINR
            }, '${order.chefName}')`
        )
        .join(", ")};`;

    await db.run(insertOrderQuery);

    response.status(200).send("Order placed successfully");
  } catch (error) {
    console.error("Error placing order:", error);
    response.status(500).send("Internal Server Error");
  }
});

//API FOR CUSTOMER REGISTER
app.post("/register", async (request, response) => {
  const { username, password } = request.body;
  const checkUserQuery = `
    SELECT customername FROM customer_credentials WHERE customername = ?;
  `;

  try {
    const existingUser = await db.get(checkUserQuery, [username]);
    if (existingUser) {
      return response
        .status(409)
        .json({ error_msg: "Username already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertUserQuery = `
      INSERT INTO customer_credentials (customername, customerpassword)
      VALUES (?, ?);
    `;

    await db.run(insertUserQuery, [username, hashedPassword]);
    response.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error registering user:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

//API FOR ADMIN TO REGISTER

app.post("/adminregister", async (request, response) => {
  const { username, password } = request.body;

  try {
    const checkAdminQuery = `
      SELECT Admin_name FROM Admin WHERE Admin_name = ?;
    `;
    const existingAdmin = await db.get(checkAdminQuery, [username]);

    if (existingAdmin) {
      return response
        .status(400)
        .json({ error_msg: "Admin name already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const insertUserQuery = `
      INSERT INTO Admin (Admin_name, Admin_password)
      VALUES (?, ?);
    `;
    await db.run(insertUserQuery, [username, hashedPassword]);

    response.status(201).json({ message: "Admin registered successfully" });
  } catch (error) {
    console.error("Error registering admin:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

//API for admin login

app.post("/adminlogin", async (request, response) => {
  const { username, password } = request.body;
  console.log("Username:", username);
  console.log("Password:", password);
  const selectUserQuery = `
    SELECT *
    FROM Admin
    WHERE Admin_name = ?;`;

  try {
    const dbUser = await db.get(selectUserQuery, [username]);

    console.log("Database User:", dbUser);
    if (dbUser === undefined) {
      return response
        .status(401)
        .json({ error_msg: "Invalid username or password" });
    }

    const isPasswordMatch = await bcrypt.compare(
      password,
      dbUser.Admin_password
    );

    console.log("Password Match:", isPasswordMatch);

    if (!isPasswordMatch) {
      console.log("Invalid password");
      return response
        .status(401)
        .json({ error_msg: "Invalid username or password" });
    }

    const payload = { username };
    const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");

    response.status(200).json({ jwtToken });
  } catch (error) {
    console.error("Error verifying credentials:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

//API FOR ADMIN TO GET ORDERS

app.get("/admin/orders", authenticateToken, async (request, response) => {
  const getOrdersQuery = `
    SELECT customer_name, food_name, chef_name, COUNT(food_id) as total_items, SUM(quantity_cost) as total_cost, SUM(quantity) as total_quantity
    FROM orders
    GROUP BY customer_name, food_name, chef_name;
  `;

  try {
    const orders = await db.all(getOrdersQuery);
    const groupedOrders = orders.reduce((acc, order) => {
      if (!acc[order.customer_name]) {
        acc[order.customer_name] = {
          customer_name: order.customer_name,
          items: [],
          total_cost: 0,
          total_quantity: 0,
        };
      }
      acc[order.customer_name].items.push({
        food_name: order.food_name,
        total_items: order.total_items,
        total_quantity: order.total_quantity,
        chef: order.chef_name, // Include chef_name
      });
      acc[order.customer_name].total_cost += order.total_cost;
      acc[order.customer_name].total_quantity += order.total_quantity;
      return acc;
    }, {});

    response.status(200).json(Object.values(groupedOrders));
  } catch (error) {
    console.error("Error fetching orders:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

//API FOR ADMIN TO DELETE ORDERS

app.delete("/admin/orders/:customerName", async (request, response) => {
  const { customerName } = request.params;

  try {
    const deleteOrdersQuery = `
      DELETE FROM orders
      WHERE customer_name = ?;
    `;
    await db.run(deleteOrdersQuery, [customerName]);
    response.status(200).send("Orders deleted successfully");
  } catch (error) {
    console.error("Error deleting orders:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

//API FOR KITCHEN REGISTER

app.post("/kitchenregister", async (request, response) => {
  const { username, password } = request.body;

  try {
    const checkExistingQuery = `
      SELECT * FROM kitchen WHERE kitchen_name = ?;
    `;
    const existingUser = await db.get(checkExistingQuery, [username]);

    if (existingUser) {
      return response
        .status(400)
        .json({ error_msg: "Kitchen name already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const insertUserQuery = `
      INSERT INTO kitchen (kitchen_name, kitchen_password)
      VALUES (?, ?);
    `;

    await db.run(insertUserQuery, [username, hashedPassword]);

    response.status(201).json({ message: "Kitchen registered successfully" });
  } catch (error) {
    console.error("Error registering kitchen:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});
//API FOR KITCHEN LOGIN

app.post("/kitchenlogin", async (request, response) => {
  const { username, password } = request.body;
  console.log("Username:", username);
  console.log("Password:", password);
  const selectUserQuery = `
    SELECT *
    FROM kitchen
    WHERE kitchen_name = ?;`;

  try {
    const dbUser = await db.get(selectUserQuery, [username]);

    console.log("Database User:", dbUser);
    if (dbUser === undefined) {
      return response
        .status(401)
        .json({ error_msg: "Invalid username or password" });
    }

    const isPasswordMatch = await bcrypt.compare(
      password,
      dbUser.kitchen_password
    );

    console.log("Password Match:", isPasswordMatch);

    if (!isPasswordMatch) {
      console.log("Invalid password");
      return response
        .status(401)
        .json({ error_msg: "Invalid username or password" });
    }

    const payload = { username };
    const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");

    response.status(200).json({ jwtToken });
  } catch (error) {
    console.error("Error verifying credentials:", error);
    response.status(500).json({ error_msg: "Internal Server Error" });
  }
});

module.exports = app;
