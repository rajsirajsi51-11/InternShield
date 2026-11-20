# InternShield — Setup Guide

## Prerequisites
- Node.js 18+
- npm
- Firebase and Groq accounts for cloud features (the local rule-based scan works without Groq)

---

## 1. Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com) → Create project
2. Enable **Firestore Database**. Apply the rules from `firestore.rules` in the Firebase Console (Firestore → Rules). This allows signed-in users to read only their own scans; scan writes stay server-side.
3. Go to **Project Settings → Service Accounts** → Generate new private key
   - Download the JSON file
   - Copy its content as a single line for `FIREBASE_SERVICE_ACCOUNT`
4. Go to **Project Settings → General** → Your apps → Add Web App
   - Copy the `firebaseConfig` values
5. Go to **Authentication → Sign-in method** and enable **Email/Password** and **Google**
6. Add the deployed site hostname under **Authentication → Settings → Authorized domains**

---

## 2. Groq API Key

1. Go to [console.groq.com](https://console.groq.com)
2. Create an API key
3. Copy it for `GROQ_API_KEY`

---

## 3. Environment Variables

### Frontend (`.env.local` in project root)
```
VITE_FIREBASE_API_KEY=...
VITE_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your-project-id
VITE_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=...
VITE_FIREBASE_APP_ID=...
```

Keep environment files out of source control. The `VITE_FIREBASE_*` values are Firebase's browser-app configuration; never put service-account credentials or API secrets in these variables.

### Backend (Netlify Functions — set in Netlify Dashboard)
```
GROQ_API_KEY=gsk_...
FIREBASE_SERVICE_ACCOUNT={"type":"service_account","project_id":"..."}
```

For **local dev**, create `netlify/.env`:
```
GROQ_API_KEY=gsk_...
FIREBASE_SERVICE_ACCOUNT={"type":"service_account",...}
```

---

## 4. Local Development

```bash
# Install frontend and local Netlify CLI
npm install

# Install function deps
cd netlify/functions
npm install
cd ../..

# In terminal 1, start Vite
npm run dev

# In terminal 2, start the Netlify functions server
npm run dev:functions
```

Visit http://localhost:5173. The Vite server proxies analysis requests to the local functions server on port 9999.

---

## 5. Deploy to Netlify

```bash
# Login
netlify login

# Initialize (first time)
netlify init

# Set env vars
netlify env:set GROQ_API_KEY "gsk_..."
netlify env:set FIREBASE_SERVICE_ACCOUNT '{"type":"service_account",...}'

# Deploy
netlify deploy --prod
```

Or just push to GitHub and connect the repo in Netlify Dashboard.

---

## 6. Firestore Security Rules

Copy `firestore.rules` into Firebase Console → Firestore → Rules and publish them. These rules match the app's history screen: a signed-in user can read scans whose `userId` matches their Firebase UID, while all client writes are denied. The Netlify function verifies Firebase ID tokens before associating scans with an account.
