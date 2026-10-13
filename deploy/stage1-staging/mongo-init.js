// Empty staging database only. No production restore or root user for the app.
const name = process.env.MONGO_INITDB_DATABASE;
if (name !== 'nivxray_stage1_staging') throw new Error('Wrong staging database');
if (!process.env.STAGING_MONGO_USER || !process.env.STAGING_MONGO_PASSWORD)
  throw new Error('Staging application database credentials missing');
db.getSiblingDB(name).createUser({
  user: process.env.STAGING_MONGO_USER,
  pwd: process.env.STAGING_MONGO_PASSWORD,
  roles: [{role: 'readWrite', db: name}]
});
