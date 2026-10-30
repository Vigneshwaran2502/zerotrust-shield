import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { hashPassword, generateSecureTempPassword } from './src/server/crypto.js';

async function generateSeed() {
  console.log('Generating fresh credentials for demo accounts...\n');

  const adminPassword = generateSecureTempPassword();
  const facultyPassword = generateSecureTempPassword();
  const studentPassword = generateSecureTempPassword();

  const [adminHash, facultyHash, studentHash] = await Promise.all([
    hashPassword(adminPassword),
    hashPassword(facultyPassword),
    hashPassword(studentPassword)
  ]);

  const sql = `
-- Fresh Demo Accounts for ZeroTrust Shield D1
INSERT INTO users (id, name, email, password, role) VALUES 
('ADM-2026-0001', 'System Administrator', 'admin@zerotrustcampus.edu', '${adminHash}', 'Administrator'),
('ADM-2026-0002', 'Vigneshwaran (Admin)', 'vigneshwaran7002@gmail.com', '${adminHash}', 'Administrator'),
('FAC-2026-0001', 'Prof. Alan Turing', 'faculty@zerotrustcampus.edu', '${facultyHash}', 'Faculty'),
('STU-2026-0001', 'Alex Mercer', 'student@zerotrustcampus.edu', '${studentHash}', 'Student')
ON CONFLICT(email) DO NOTHING;
`.trim();

  const seedFilePath = path.resolve('d1-seed.sql');
  fs.writeFileSync(seedFilePath, sql, 'utf-8');

  console.log('=================================================================');
  console.log('        ONE-TIME DEMO ACCOUNT CREDENTIALS (SAVE THESE)          ');
  console.log('=================================================================');
  console.log(`1. Administrator:`);
  console.log(`   Email:    admin@zerotrustcampus.edu`);
  console.log(`   Email:    vigneshwaran7002@gmail.com`);
  console.log(`   Password: ${adminPassword}\n`);

  console.log(`2. Faculty:`);
  console.log(`   Email:    faculty@zerotrustcampus.edu`);
  console.log(`   Password: ${facultyPassword}\n`);

  console.log(`3. Student:`);
  console.log(`   Email:    student@zerotrustcampus.edu`);
  console.log(`   Password: ${studentPassword}`);
  console.log('=================================================================\n');

  console.log(`Generated d1-seed.sql with secure bcrypt hashes.`);
  console.log(`To execute on remote D1:`);
  console.log(`  npx wrangler d1 execute zerotrust-shield-db --remote --file=./d1-seed.sql\n`);
}

generateSeed().catch(err => {
  console.error(err);
  process.exit(1);
});
