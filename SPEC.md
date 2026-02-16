# AI-Adaptive Password & Social Engineering Simulator

## Project Overview

**Project Name:** CyberShield AI-Adaptive Security Simulator  
**Type:** Educational Security Training Web Application  
**Core Functionality:** Real-time interactive simulator that demonstrates how password attacks and social engineering work, adapting to user behavior to provide personalized security training  
**Target Users:** Security professionals, IT teams, employees, students learning cybersecurity awareness

---

## UI/UX Specification

### Layout Structure

**Main Navigation:**
- Fixed sidebar navigation (280px width) with animated icons
- Main content area with glass-morphism panels
- Floating real-time status indicators
- Collapsible on mobile (hamburger menu)

**Page Sections:**
1. **Dashboard** - Real-time threat overview, security score, recent activity
2. **Password Lab** - Interactive password strength analyzer with attack simulation
3. **Social Engineering Arena** - Phishing email simulator, voice call scenarios
4. **Attack Simulation** - AI-driven attack scenarios with adaptive difficulty
5. **Training Center** - Learning modules with progress tracking
6. **Analytics** - Detailed metrics and improvement tracking
7. **Settings** - Customization and preferences

### Responsive Breakpoints
- Desktop: 1200px+ (full sidebar)
- Tablet: 768px-1199px (collapsed sidebar)
- Mobile: <768px (bottom navigation)

### Visual Design

**Color Palette:**
- Primary Background: #0a0e17 (deep space black)
- Secondary Background: #111827 (dark slate)
- Glass Panels: rgba(17, 24, 39, 0.7) with backdrop blur
- Primary Accent: #00ff88 (cyber green - success/safe)
- Secondary Accent: #ff3366 (warning red - danger/attack)
- Tertiary Accent: #00d4ff (electric blue - info/neutral)
- Warning: #ffaa00 (amber)
- Text Primary: #ffffff
- Text Secondary: #94a3b8
- Border Glow: rgba(0, 255, 136, 0.3)

**Typography:**
- Headings: 'Orbitron', sans-serif (futuristic tech feel)
- Body: 'Exo 2', sans-serif
- Monospace (code/passwords): 'Fira Code', monospace
- H1: 2.5rem, weight 700
- H2: 1.75rem, weight 600
- H3: 1.25rem, weight 600
- Body: 1rem, weight 400
- Small: 0.875rem

**Spacing System:**
- Base unit: 8px
- Panel padding: 24px
- Section gap: 32px
- Component gap: 16px

**Visual Effects:**
- Glass-morphism panels with 12px border-radius
- Neon glow effects on interactive elements (box-shadow with accent colors)
- Animated gradient borders on focus
- Particle background effect (subtle network visualization)
- Pulse animations for threat indicators
- Smooth 300ms transitions on all interactive elements
- Matrix-style falling code animation in header

### Components

**1. Security Score Gauge**
- Circular progress indicator (0-100)
- Animated fill with gradient
- Color changes based on score (red < 40, yellow 40-70, green > 70)
- Tooltip with breakdown

**2. Attack Type Cards**
- Icon with glow effect
- Title and description
- Difficulty indicator (1-5 shields)
- Success rate percentage
- Hover: scale(1.02) with enhanced glow

**3. Password Analyzer**
- Real-time strength meter (5 segments)
- Character composition display
- Time-to-crack estimate (animated counter)
- Suggestions panel with AI recommendations
- Common pattern detection

**4. Phishing Email Simulator**
- Email preview panel
- Clickable elements with hover effects
- Red flag indicators (highlight suspicious elements)
- Scoring based on identification accuracy

**5. AI Chatbot Attack Simulator**
- Conversational interface
- Message bubbles with timestamps
- Typing indicator animation
- Context-aware responses

**6. Training Progress Cards**
- Module icon
- Progress bar with glow
- Completion percentage
- Time remaining estimate

**7. Real-time Log Panel**
- Scrollable terminal-style display
- Color-coded log levels
- Timestamp for each entry
- Filter options

---

## Functionality Specification

### Core Features

#### 1. AI-Adaptive Password Analyzer
- Real-time password strength evaluation
- Character analysis (uppercase, lowercase, numbers, symbols)
- Pattern detection (keyboard walks, repeated chars, dates)
- Dictionary word detection
- Time-to-crack calculation using multiple attack scenarios:
  - Brute force (online/offline)
  - Dictionary attack
  - Rainbow table attack
  - GPU-accelerated attack
- Personalized improvement suggestions
- Password history analysis (for logged users)

#### 2. Social Engineering Attack Simulator

**Phishing Email Module:**
- Template-based email generation
- Multiple attack vectors:
  - Credential harvesting
  - Malware attachment
  - Fake login page
  - CEO fraud/Business Email Compromise
- Difficulty levels: Beginner, Intermediate, Advanced, Expert
- Real-time email analysis tools
- Red flag identification training
- Score tracking per attempt

**Voice Phishing (Vishing) Simulator:**
- Script-based conversation scenarios
- Multiple scenarios (IT support, CEO, vendor)
- Decision points during conversation
- Audio cues for emotional manipulation
- Post-call analysis

**SMS/Text Phishing (Smishing):**
- Short message scenarios
- Link analysis training
- Urgency indicator detection
- Sender verification tips

#### 3. AI-Driven Attack Engine
- Adaptive difficulty based on user performance
- Multiple attack vectors that evolve:
  - Password guessing with learned patterns
  - Personalized phishing based on user profile
  - Context-aware social engineering
- Real-time attack visualization
- Defense recommendation engine
- Attack pattern learning (simulates real AI threats)

#### 4. Training & Education Center

**Learning Modules:**
- Password Security Fundamentals
- Recognizing Phishing Attempts
- Social Engineering Awareness
- Data Protection Best Practices
- Incident Response Training

**Interactive Elements:**
- Quiz-based assessments
- Scenario-based challenges
- Gamified learning with points
- Achievement system
- Certification tracking

#### 5. Real-Time Analytics Dashboard

**Metrics Displayed:**
- Security score over time (line chart)
- Attack detection rate (pie chart)
- Training completion status
- Weak password alerts
- Recent activity log
- Comparative performance metrics

**Advanced Features:**
- Risk score calculation
- Vulnerability assessment
- Improvement recommendations
- Export reports (PDF/CSV)

### User Interactions and Flows

**Initial User Flow:**
1. Welcome screen with feature overview
2. Quick security assessment quiz
3. Personalized dashboard based on initial score
4. Recommended training path

**Password Analysis Flow:**
1. User enters test password
2. Real-time strength meter updates
3. Attack simulation runs in background
4. Results displayed with recommendations
5. User can click for detailed breakdown

**Phishing Training Flow:**
1. User selects difficulty level
2. Email/scenario presented
3. User analyzes for red flags
4. Click to reveal answer
5. Score and explanation provided
6. Related training module suggested

### Data Handling
- All analysis performed client-side (privacy-focused)
- Optional local storage for progress tracking
- No sensitive data transmitted
- Session-based analytics

### Edge Cases
- Handle very long passwords (truncate display)
- Handle special characters in display
- Mobile-friendly terminal output
- Offline functionality for core features
- Accessibility considerations (screen reader support)

---

## Acceptance Criteria

### Visual Checkpoints
- [ ] Dark cyber-security theme consistently applied
- [ ] Glass-morphism panels render correctly
- [ ] Animations are smooth (60fps)
- [ ] All icons display properly
- [ ] Responsive on all breakpoints
- [ ] Matrix rain animation visible in header

### Functional Checkpoints
- [ ] Password analyzer provides real-time feedback
- [ ] Time-to-crack calculations are accurate
- [ ] At least 5 phishing scenarios available
- [ ] AI adaptation responds to user performance
- [ ] Training modules track progress
- [ ] Analytics display real-time updates
- [ ] All interactive elements respond to hover/click

### Performance Checkpoints
- [ ] Initial load under 3 seconds
- [ ] Real-time updates without lag
- [ ] Smooth transitions between sections
- [ ] No console errors on load

---

## Technical Implementation

**Stack:** Single HTML file with embedded CSS and JavaScript  
**Libraries:** None (vanilla JS for maximum compatibility)  
**Storage:** LocalStorage for progress persistence  
**No external dependencies except fonts (Google Fonts CDN)