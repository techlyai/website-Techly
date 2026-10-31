"use strict";
// Create (or reset) an Owner admin account.
// Usage: npm run create-owner -- <email> <password> [name]
require("dotenv").config();
const bcrypt = require("bcryptjs");
const { MongoClient } = require("mongodb");

(async () => {
  const [email, password, ...nameParts] = process.argv.slice(2);
  if (!email || !password) { console.error("Usage: npm run create-owner -- <email> <password> [name]"); process.exit(1); }
  if (password.length < 8) { console.error("Password needs at least 8 characters"); process.exit(1); }
  const e = email.trim().toLowerCase();
  const name = nameParts.join(" ") || e.split("@")[0];
  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  const Admins = client.db(process.env.MONGODB_DB || "techly").collection("admins");
  await Admins.createIndex({ email: 1 }, { unique: true });
  const prev = await Admins.findOne({ email: e });
  await Admins.updateOne(
    { email: e },
    {
      $set: { name, role: "Owner", active: true, passwordHash: await bcrypt.hash(password, 12), tokenVersion: (prev?.tokenVersion || 0) + 1 },
      $setOnInsert: { email: e, createdAt: new Date(), createdBy: "create-owner script" }
    },
    { upsert: true }
  );
  console.log(`${prev ? "Updated" : "Created"} Owner: ${e}`);
  await client.close();
})().catch(err => { console.error(err.message); process.exit(1); });
