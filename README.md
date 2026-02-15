# NeoBank Frontend + OTP Mail Flow

This project includes:
- User/Admin login views
- Forgot MPIN with OTP sent via email
- User banking dashboard
- Admin dashboard with cyberattack graph and fraud table

## Run

1. Install dependencies:
   ```bash
   npm install
   ```
2. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   Set `SMTP_PASS` to the Gmail App Password for `neobank399@gmail.com`.
3. Start app:
   ```bash
   npm start
   ```
4. Open `http://localhost:5000`

## Notes
- OTP emails are sent from `neobank399@gmail.com` when SMTP is configured.
- OTP expires in 5 minutes and is single-use.
