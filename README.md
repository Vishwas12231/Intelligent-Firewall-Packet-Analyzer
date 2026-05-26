# Intelligent Firewall & Packet Analyzer

An elegant full-stack web application designed to monitor simulated network packets, create and enforce active firewall rules, trigger alerts for malicious traffic, and utilize advanced Gemini generative AI capabilities to analyze individual packet structures and recommend customized security filters.

---

## 🚀 Quick Local Setup & Installation

Get the application running on your local machine in just a few steps.

### Prerequisites
Make sure you have [Node.js](https://nodejs.org/) installed on your machine (v18 or newer is recommended).

### 1. Extract and Navigate
Download the zip file, extract it to your preferred location, and open your terminal (Command Prompt, PowerShell, or macOS/Linux Terminal) in the project directory:
```bash
cd "C:\Users\i7.11TH\Downloads\intelligent-firewall-&-packet-analyzer"
```

### 2. Install Project Dependencies
Run the installation command to download all necessary npm packages:
```bash
npm install
```

### 3. Configure Local Credentials
Create a `.env` file in the root directory by copying the template file:
```bash
# On Windows PowerShell:
copy .env.example .env

# On macOS/Linux or Git Bash:
cp .env.example .env
```
Open the `.env` file in any text editor (VS Code, Notepad, etc.) and specify your credentials:
```env
GEMINI_API_KEY="your_real_gemini_api_key"
APP_URL="http://localhost:3000"
```
> **Note:** To obtain a free Gemini API key, go to the [Google AI Studio Console](https://aistudio.google.com/).

---

## 💻 Running the Application Locally

The codebase is fully optimized to run seamlessly across all operating systems—including Windows systems with restrictive script execution policies.

### Local Development Mode
Start the front-end preview and back-end packet simulator by executing:
```bash
npm run dev
```

#### Why this works perfectly on Windows:
We modified the dev trigger to use `node --import tsx server.ts` directly. This altogether circumvents the restrictive Windows PowerShell PowerShell execution policies (`UnauthorizedAccess` / `tsx.ps1 cannot be loaded`) and runs without requiring administrative privileges!

Access the UI locally in your web browser at: **`http://localhost:3000`**

---

## 📦 Building the Project (Cross-Platform)

When building the application for production, run:
```bash
npm run build
```

#### No More PowerShell Builder Script Failures:
Rather than chaining raw shell commands (like `vite build && esbuild...`) which crash under certain environments (like Windows PowerShell which doesn't support the `&&` token by default, or blocks `vite.ps1`), we implemented a **Programmatic JS Builder** (`build.js`). 

Executing `npm run build` launches this builder, executing:
1. **Vite bundling** of frontend files programmatically into `/dist`.
2. **esbuild bundling** of backend modules programmatically into a clean, standalone, unified, output CJS file at `/dist/server.cjs`.

---

## ☁️ Deploying to Production (100% Free Lifetime Hosting)

Because this application operates on a **full-stack architecture** (consisting of a React client and a Node.js Express server simulator), it requires two components:
1. **Static Frontend Hosting** (e.g., Netlify)
2. **Server-Side Backend Hosting** (e.g., Render or Railway Free Tiers)

---

### Option A: Fully Unified Deployment on Render (Recommended & Simplest)
Instead of splitting the app, you can host your complete full-stack app on **Render** under their free tier with a single click.

1. **Upload your code** to a private or public GitHub repository.
2. Sign in to [Render](https://render.com/) (Free).
3. Click **New +** > **Web Service**.
4. Connect your GitHub repository.
5. Apply the following configurations:
   - **Environment:** `Node`
   - **Build Command:** `npm run build`
   - **Start Command:** `npm run start`
6. Under **Environment Variables**, add:
   - `GEMINI_API_KEY` = `(your API key)`
   - `NODE_ENV` = `production`
7. Click **Deploy Web Service**. You get a live full-stack app running on a free subdomain (e.g., `https://your-firewall.onrender.com`)!

---

### Option B: Split Deployment (Netlify Frontend + Render Backend)

If you strictly wish to host the user-interface on **Netlify**, use this approach. Netlify will serve the static files, and proxy all `/api/*` traffic to a free hosted backend instance on Render.

#### Step 1: Deploy the Backend (on Render.com)
1. Sign in to [Render](https://render.com/).
2. Click **New +** > **Web Service** and connect your GitHub repository.
3. Configure the following build & launch settings:
   - **Build Command:** `npm run build`
   - **Start Command:** `npm run start`
4. Add your **Environment Variables**:
   - `GEMINI_API_KEY` = `(your api key)`
   - `APP_URL` = `(your Netlify site URL after creating it)`
5. Click **Deploy** and copy your backend URL (e.g., `https://your-firewall-backend.onrender.com`).

#### Step 2: Configure Route Redirects in the Frontend
Open the `/public/_redirects` file in your workspace. Update line 1 to redirect all API calls from Netlify straight to your live Render backend URL:
```text
/api/*  https://your-firewall-backend.onrender.com/api/:splat  200!
```
*(Ensure there is a space between the route matches, and that the rule ends in `200!` to force the proxy bypass).*

#### Step 3: Deploy the Frontend (on Netlify)
1. Sign into [Netlify](https://www.netlify.com/) (using your free account).
2. Go to **Sites** > Click **Add new site** > **Deploy manually**.
3. Re-run `npm run build` on your desktop to compile with the updated changes.
4. Drag and drop the compiled **`dist`** folder (located inside your project folder) onto the Netlify dashboard upload block.
5. In your Netlify site settings, set your Custom Domain or use their free randomized domain (e.g., `https://intelligent-firewall.netlify.app`).

*Your frontend will load lightning-fast from Netlify's globally distributed CDN, and Netlify's reverse proxy will secure all packet logging, firewall switches, and AI generative sessions via your free Render backend, safely keeping your Gemini API Key hidden from the client browser console!*

---

## 🛠️ Diagnostics & Troubleshooting

| Error Encountered | Root Cause | Ultimate Remedy |
| :--- | :--- | :--- |
| `SecurityError: UnauthorizedAccess` (PowerShell) | PowerShell scripts (`tsx.ps1` or `vite.ps1`) are blocked locally. | Run `npm run dev` or `npm run build`. We updated both scripts in `package.json` to bypass direct script execution completely using standard node runtime bindings! |
| `'&&' is not a valid statement separator` | Using macOS/Linux command chaining in simple Windows standard terminals. | Use our programmatic build script (`npm run build`) which executes Vite and esbuild internally through JS. |
| `API key should be set key` warnings | You did not set up the local `.env` environment variables correctly. | Create a `.env` in the root and add your real `GEMINI_API_KEY` token. |

---

## 🧬 Tech Stack Used

- **Client Face:** React 19, Tailwind CSS 4, Motion, Lucide Icons, Recharts
- **Server Engine:** Express, Node, esbuild, Programmatic Vite compiler, `@google/genai` (Official Google Generative AI SDK)
