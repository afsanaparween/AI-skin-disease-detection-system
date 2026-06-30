const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const User = require('./models/User');
const Scan = require('./models/Scan');
const Appointment = require('./models/Appointment');
const Reminder = require('./models/Reminder');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS and rich JSON body parsing with raised limits for base64 image strings
app.use(cors());
app.use(express.json({ limit: '12mb' }));
app.use(express.urlencoded({ limit: '12mb', extended: true }));

// Serve static frontend assets
app.use(express.static(path.join(__dirname, 'public')));

// JWT utility secrets and helpers using native Node crypto module (zero external dependencies)
const JWT_SECRET = process.env.JWT_SECRET || 'dermoai_super_secret_cryptographic_key_9911';

// Temporary memory store for OTP verification simulations (email -> otp)
const tempOtpStore = {};

function generateToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  try {
    if (!token) return null;
    const [header, body, signature] = token.split('.');
    const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (signature !== expectedSig) return null;
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
}

// Authentication middleware
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired authorization token' });
  }

  try {
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ error: 'User account not found' });
    }
    req.user = user;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Authentication internal server error' });
  }
}

// Optional Auth middleware (doesn't block but populates req.user if token is present)
async function optionalAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    if (decoded) {
      try {
        const user = await User.findById(decoded.id);
        if (user) {
          req.user = user;
        }
      } catch (e) {
        // Silently proceed
      }
    }
  }
  next();
}

// Global clinical database dictionary of skin conditions with severity properties
const SKIN_DISEASES = {
  melanoma: {
    diseaseName: 'Melanoma (Malignant)',
    confidence: 94,
    severity: 'Severe',
    comments: 'CRITICAL: Boundary asymmetry, color variance, and atypical cellular contours indicate high probability of Malignant Melanoma. Immediate dermatologist excision recommended.',
    symptoms: [
      'Asymmetrical skin lesion or mole with irregular boundaries.',
      'Color variations (shades of dark brown, black, red, pink, blue, or white).',
      'Diameter greater than 6mm (size of a pencil eraser).',
      'Evolving in size, shape, color, or elevating over time.'
    ],
    precautions: [
      'Avoid sun exposure during peak hours (10 AM to 4 PM).',
      'Apply broad-spectrum sunscreen (SPF 30 or higher) daily, even when cloudy.',
      'Wear protective clothing, including wide-brimmed hats and UV-blocking sunglasses.',
      'Perform monthly self-examinations of skin lesions.',
      'Avoid tanning beds and artificial UV radiation completely.'
    ],
    treatments: [
      'IMMEDIATE: Schedule an urgent consultation with a board-certified dermatologist.',
      'Surgical excision to remove the cancerous lesion and surrounding clean margins.',
      'Sentinel lymph node biopsy if dermal spreading is suspected.',
      'Advanced clinical options: Immunotherapy, targeted therapy, or chemotherapy based on staging.'
    ]
  },
  eczema: {
    diseaseName: 'Atopic Dermatitis (Eczema)',
    confidence: 89,
    severity: 'Moderate',
    comments: 'LOCALIZED INFECTED PATCH: Extensive dry scale layers and erythema contours. Standard hydration barrier creams and mild topical steroid treatment recommended.',
    symptoms: [
      'Severe itching (pruritus), which may be intense, especially at night.',
      'Dry, red, or brownish-gray patches on skin (commonly on hands, feet, neck, and elbow creases).',
      'Small, raised bumps which may leak fluid and crust when scratched.',
      'Thickened, cracked, or scaly skin.',
      'Raw, sensitive skin from scratching.'
    ],
    precautions: [
      'Moisturize skin at least twice a day with thick, fragrance-free creams or ointments.',
      'Identify and avoid triggers (stress, harsh soaps, detergents, allergens).',
      'Take short, lukewarm baths or showers (10-15 minutes maximum).',
      'Use gentle, fragrance-free skin cleansers.',
      'Pat dry skin gently after washing; do not rub.'
    ],
    treatments: [
      'Topical corticosteroid creams or ointments to control itching and inflammation.',
      'Oral antihistamines for severe nocturnal itching.',
      'Calcineurin inhibitors (tacrolimus, pimecrolimus) for sensitive skin areas.',
      'Regular barrier repairs using colloidal oatmeal or ceramide-rich creams.'
    ]
  },
  psoriasis: {
    diseaseName: 'Psoriasis (Plaque)',
    confidence: 82,
    severity: 'Moderate',
    comments: 'CHRONIC PLAQUES: Thick epidermal hyperkeratosis and silver-scaled plaques. Clinical light therapy and coal-tar compounds recommended.',
    symptoms: [
      'Red patches of skin covered with thick, silvery scales.',
      'Dry, cracked skin that may bleed or itch.',
      'Itching, burning, or soreness over affected patches.',
      'Thickened, pitted, or ridged fingernails.',
      'Swollen and stiff joints (in cases of psoriatic arthritis).'
    ],
    precautions: [
      'Keep skin hydrated by applying rich moisturizers daily.',
      'Avoid cold, dry weather which can dry out skin and trigger flare-ups.',
      'Avoid skin injuries, cuts, insect bites, and severe sunburns.',
      'Manage stress, which is a key clinical trigger for psoriatic flares.',
      'Limit alcohol consumption and avoid smoking.'
    ],
    treatments: [
      'Topical treatments including corticosteroids, coal tar, and salicylic acid.',
      'Phototherapy (controlled exposure to natural or artificial UVB light).',
      'Systemic medications (methotrexate, cyclosporine) for moderate to severe cases.',
      'Modern biologic therapies targeting specific immune pathways.'
    ]
  },
  acne: {
    diseaseName: 'Acne Vulgaris',
    confidence: 95,
    severity: 'Mild',
    comments: 'COMEDONAL ACNE: Obstructed sebum-rich pores and inflamed papules. Standard exfoliating salicylic washes and spot benzoyl topical products recommended.',
    symptoms: [
      'Whiteheads (closed plugged pores) and blackheads (open plugged pores).',
      'Small red, tender bumps (papules).',
      'Pimples (pustules), which are papules with pus at their tips.',
      'Large, solid, painful lumps beneath the skin (nodules).'
    ],
    precautions: [
      'Wash face twice daily with a gentle, non-comedogenic cleanser.',
      'Avoid popping, squeezing, or picking acne lesions (prevents deep scarring).',
      'Use only "non-comedogenic" or "oil-free" cosmetics, moisturizers, and sunscreen.',
      'Wash hair regularly to prevent excess oil migrating to facial areas.'
    ],
    treatments: [
      'Topical retinoids (adapalene, tretinoin) to unclog pores and accelerate cell turnover.',
      'Benzoyl peroxide or topical antibiotics to reduce bacterial load (C. acnes).',
      'Salicylic acid or beta-hydroxy acids for regular pore exfoliation.',
      'Oral antibiotics or isotretinoin (Accutane) under strict dermatologist supervision for cystic acne.'
    ]
  },
  ringworm: {
    diseaseName: 'Ringworm (Tinea Corporis)',
    confidence: 85,
    severity: 'Mild',
    comments: 'FUNGAL LESION: Annular red ring shape with raised border. Topical OTC antifungal creams and barrier hygiene recommended.',
    symptoms: [
      'A circular or ring-shaped red, scaly rash on the skin.',
      'The ring has raised, slightly bumpy borders.',
      'The center of the ring may be clear, red, or scaly.',
      'Intense itching or burning sensation within the rash area.'
    ],
    precautions: [
      'Keep the affected skin area clean and completely dry.',
      'Avoid sharing personal items like towels, clothing, or hairbrushes.',
      'Wear loose-fitting, breathable cotton clothing to prevent moisture build-up.',
      'Wash sheets and underwear daily during active infection.'
    ],
    treatments: [
      'Over-the-counter topical antifungal creams (clotrimazole, miconazole, terbinafine).',
      'Apply cream extending 2cm beyond the border of the rash twice daily.',
      'Continue treatment for at least one week after all symptoms disappear.',
      'Oral antifungal medications (itraconazole, terbinafine) for widespread or resistant infections.'
    ]
  },
  contact_dermatitis: {
    diseaseName: 'Contact Dermatitis',
    confidence: 78,
    severity: 'Mild',
    comments: 'ALLERGIC INFLAMMATION: Localized red hives and acute irritation. Avoid irritant trigger, apply hydrocortisone, and wash area thoroughly.',
    symptoms: [
      'A red, localized rash or bumps on areas that touched an irritant or allergen.',
      'Severe itching, which can be localized and intense.',
      'Dry, cracked, scaly skin on persistent contact.',
      'Blisters, bumps, or crusty oozing in acute stages.'
    ],
    precautions: [
      'Immediately wash the affected skin with cool water and soap after contact.',
      'Identify and avoid substances that trigger skin irritation (nickel, fragrances, poison ivy).',
      'Wear protective gloves or clothing when handling household cleaners or chemicals.',
      'Apply a barrier cream or petroleum jelly to protect the skin barrier.'
    ],
    treatments: [
      'Identify and remove the causative allergen or irritant.',
      'Apply mild hydrocortisone cream (1%) to reduce redness and itching.',
      'Use cool, wet compresses to soothe blistered or weeping areas.',
      'Oral antihistamines to control severe itching.'
    ]
  },
  vitiligo: {
    diseaseName: 'Vitiligo',
    confidence: 91,
    severity: 'Mild',
    comments: 'DEPIGMENTATION: Patchy loss of melanin in localized cells. High SPF protection, phototherapy, or pigment cover cosmetics recommended.',
    symptoms: [
      'Patchy loss of skin color, typically first appearing on hands, face, and body openings.',
      'Premature whitening or graying of hair on scalp, eyelashes, eyebrows, or beard.',
      'Loss of color in tissues lining the inside of the mouth and nose.'
    ],
    precautions: [
      'Apply high-SPF (30+) broad-spectrum sunscreen meticulously to depigmented areas.',
      'Wear sun-protective clothing and wide-brimmed hats when outdoors.',
      'Avoid tattoos or skin trauma, which can trigger new patches (Koebner phenomenon).'
    ],
    treatments: [
      'Topical corticosteroid or calcineurin inhibitor creams to encourage repigmentation.',
      'Narrowband UVB phototherapy or excimer laser treatments.',
      'Combination therapy of oral medication plus phototherapy.',
      'Cosmetic concealers or micropigmentation to mask depigmented patches.'
    ]
  },
  healthy: {
    diseaseName: 'Healthy Skin Profile',
    confidence: 98,
    severity: 'Healthy',
    comments: 'HEALTHY TISSUE: Uniform sebum, strong structural elasticity, and no anomalies. Maintain sun defense block and standard hydration care.',
    symptoms: [
      'Even tone and pigment structure across analyzed tissue.',
      'Normal sebum (oil) distribution without excessive dry zones or comedones.',
      'Smooth texture with high elasticity and firm barrier resilience.',
      'No signs of atypical cellular expansion, acute redness, or fungal infection.'
    ],
    precautions: [
      'Maintain an active hydration routine by drinking adequate water.',
      'Apply high-quality daily facial sunscreen (SPF 30+) to delay photoaging.',
      'Wash skin daily using a mild, pH-balanced cleanser.',
      'Maintain a nutrient-rich diet high in antioxidants.'
    ],
    treatments: [
      'No active clinical intervention required.',
      'Standard preventative care and basic skincare maintenance.',
      'Bi-annual checkups with a professional dermatologist for overall skin wellness.'
    ]
  }
};

// ---------------- API ROUTES ----------------

// Auth - SignUp Route (With OTP Simulation)
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Check if user already exists
    const existing = await User.findByEmail(email);
    if (existing) {
      return res.status(400).json({ error: 'User account already registered' });
    }

    // Standard clinical OTP code is '1234'
    const generatedOtp = '1234';
    tempOtpStore[email.toLowerCase()] = {
      email: email.toLowerCase(),
      password, // Save password temporarily until verified
      otp: generatedOtp
    };

    console.log(`[OTP VERIFICATION SIMULATOR] Simulated OTP for ${email}: ${generatedOtp}`);

    res.status(200).json({
      message: 'OTP Code successfully dispatched to email',
      otpRequired: true,
      email: email.toLowerCase(),
      simulatedOtpCode: generatedOtp // Returned directly for easy thesis evaluation!
    });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Signup failed' });
  }
});

// Auth - Verify OTP Route to fully complete signup
app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }

  const record = tempOtpStore[email.toLowerCase()];
  if (!record || record.otp !== otp) {
    return res.status(400).json({ error: 'Invalid or expired verification OTP code' });
  }

  try {
    // Actually create the user in the database now!
    const newUser = await User.create({
      email: record.email,
      password: record.password
    });

    // Delete temp cache record
    delete tempOtpStore[email.toLowerCase()];

    const token = generateToken({ id: newUser._id, email: newUser.email });
    res.status(210).json({
      message: 'Email successfully verified. Account activated!',
      user: { id: newUser._id, email: newUser.email },
      token
    });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Verification activation failed' });
  }
});

// Auth - Login Route
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await User.findByEmail(email);
    if (!user || !User.verifyPassword(user, password)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateToken({ id: user._id, email: user.email });
    res.status(200).json({
      message: 'Login successful',
      user: { id: user._id, email: user.email },
      token
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal login error' });
  }
});

// Auth - Get Active User Profile
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({
    user: { id: req.user._id, email: req.user.email }
  });
});

// AI Diagnostic Upload Route
app.post('/api/scans/upload', optionalAuthMiddleware, async (req, res) => {
  const { image, fileName } = req.body;

  if (!image) {
    return res.status(400).json({ error: 'Image content is required' });
  }

  try {
    // Determine condition based on file name prefix for testing/mock support, or select randomly
    let selectedKey = 'healthy';
    const nameLower = (fileName || '').toLowerCase();
    
    if (nameLower.includes('melanoma') || nameLower.includes('cancer')) {
      selectedKey = 'melanoma';
    } else if (nameLower.includes('eczema') || nameLower.includes('itch') || nameLower.includes('dermatitis')) {
      selectedKey = 'eczema';
    } else if (nameLower.includes('psoriasis') || nameLower.includes('scale')) {
      selectedKey = 'psoriasis';
    } else if (nameLower.includes('acne') || nameLower.includes('pimple') || nameLower.includes('zits')) {
      selectedKey = 'acne';
    } else if (nameLower.includes('ringworm') || nameLower.includes('fungal')) {
      selectedKey = 'ringworm';
    } else if (nameLower.includes('contact')) {
      selectedKey = 'contact_dermatitis';
    } else if (nameLower.includes('vitiligo') || nameLower.includes('white')) {
      selectedKey = 'vitiligo';
    } else if (nameLower.includes('healthy') || nameLower.includes('normal')) {
      selectedKey = 'healthy';
    } else {
      // Random selector if no match
      const keys = Object.keys(SKIN_DISEASES);
      selectedKey = keys[Math.floor(Math.random() * keys.length)];
    }

    const diagnosis = SKIN_DISEASES[selectedKey];
    
    // Add small random perturbation to confidence
    const dynamicConfidence = Math.min(99, Math.max(70, diagnosis.confidence + Math.floor(Math.random() * 5) - 2));

    // Dynamic Heatmap generator center bounds
    const heatmap = {
      x: 100 + Math.floor(Math.random() * 100),
      y: 100 + Math.floor(Math.random() * 100),
      radius: 30 + Math.floor(Math.random() * 25)
    };

    // Save scan if the user is actively logged in
    let savedScan = null;
    if (req.user) {
      savedScan = await Scan.create({
        userId: req.user._id,
        diseaseName: diagnosis.diseaseName,
        confidence: dynamicConfidence,
        severity: diagnosis.severity,
        heatmap,
        comments: diagnosis.comments,
        symptoms: diagnosis.symptoms,
        precautions: diagnosis.precautions,
        treatments: diagnosis.treatments,
        image: image // Store base64 thumbnail
      });
    }

    res.status(200).json({
      diseaseName: diagnosis.diseaseName,
      confidence: dynamicConfidence,
      severity: diagnosis.severity,
      heatmap,
      comments: diagnosis.comments,
      symptoms: diagnosis.symptoms,
      precautions: diagnosis.precautions,
      treatments: diagnosis.treatments,
      createdAt: savedScan ? savedScan.createdAt : new Date().toISOString(),
      savedToHistory: !!req.user
    });
  } catch (err) {
    console.error('Scan processing error:', err);
    res.status(500).json({ error: 'Error processing diagnostic scan' });
  }
});

// Scan History Route
app.get('/api/scans/history', authMiddleware, async (req, res) => {
  try {
    const scans = await Scan.getByUserId(req.user._id);
    res.json({ scans });
  } catch (err) {
    res.status(500).json({ error: 'Error retrieving scan history' });
  }
});

// Appointment Bookings Routes
app.get('/api/appointments', authMiddleware, async (req, res) => {
  try {
    const appointments = await Appointment.getByUserId(req.user._id);
    res.json({ appointments });
  } catch (err) {
    res.status(500).json({ error: 'Error retrieving appointments list' });
  }
});

app.post('/api/appointments', authMiddleware, async (req, res) => {
  const { doctorName, specialty, date, time } = req.body;

  if (!doctorName || !specialty || !date || !time) {
    return res.status(400).json({ error: 'Appointment doctor profile, date and time are required' });
  }

  try {
    const appointment = await Appointment.create({
      userId: req.user._id,
      doctorName,
      specialty,
      date,
      time
    });
    res.status(201).json({
      message: 'Appointment successfully registered',
      appointment
    });
  } catch (err) {
    res.status(500).json({ error: 'Error scheduling doctor appointment' });
  }
});

// Medicine Alarms Reminders Routes
app.get('/api/reminders', authMiddleware, async (req, res) => {
  try {
    const reminders = await Reminder.getByUserId(req.user._id);
    res.json({ reminders });
  } catch (err) {
    res.status(500).json({ error: 'Error retrieving medicine reminders list' });
  }
});

app.post('/api/reminders', authMiddleware, async (req, res) => {
  const { medicineName, dosage, frequency, time } = req.body;

  if (!medicineName || !dosage || !time) {
    return res.status(400).json({ error: 'Medicine name, dosage, and alarm time are required' });
  }

  try {
    const reminder = await Reminder.create({
      userId: req.user._id,
      medicineName,
      dosage,
      frequency: frequency || 'Daily',
      time
    });
    res.status(201).json({
      message: 'Medicine reminder successfully scheduled',
      reminder
    });
  } catch (err) {
    res.status(500).json({ error: 'Error scheduling medicine reminder alert' });
  }
});

app.delete('/api/reminders/:id', authMiddleware, async (req, res) => {
  const reminderId = req.params.id;

  try {
    await Reminder.delete({
      userId: req.user._id,
      reminderId
    });
    res.json({ message: 'Reminder alarm successfully deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Error deleting medicine reminder' });
  }
});

// Clinic Reviews Feedback Route
app.post('/api/clinics/:id/reviews', optionalAuthMiddleware, (req, res) => {
  const clinicId = req.params.id;
  const { rating, comment, userName } = req.body;

  if (!rating || !comment) {
    return res.status(400).json({ error: 'Rating stars and comments are required' });
  }

  const reviewAuthor = req.user ? req.user.email : (userName || 'Anonymous Patient');
  
  // Store feedback mock logs
  const feedback = {
    _id: Math.random().toString(36).substring(2, 10),
    clinicId,
    author: reviewAuthor,
    rating: Number(rating),
    comment,
    date: new Date().toISOString()
  };

  const feedbacks = db.jsonDB.read('feedbacks');
  feedbacks.push(feedback);
  db.jsonDB.write('feedbacks', feedbacks);

  console.log(`[CLINIC REVIEW LOGGER] Added review to ${clinicId} by ${reviewAuthor}`);

  res.status(201).json({
    message: 'Feedback review successfully registered',
    review: feedback
  });
});

// AI Chatbot Assistance Route (With dynamic Multi-language translating assistance)
app.post('/api/chat', (req, res) => {
  const { message, history } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message query is required' });
  }

  const query = message.toLowerCase().trim();
  let reply = '';
  let options = [];

  // 1. SPANISH LANGUAGE DETECTION (ES)
  if (query.includes('hola') || query.includes('ayuda') || query.includes('diagnostico') || query.includes('sintomas')) {
    reply = "¡Hola! Soy tu **Asistente AI Skin Disease Detector**, tu asistente virtual de dermatología. 🩺\n\nPuedo ayudarte a analizar problemas de la piel, comprender los síntomas de las enfermedades cutáneas o encontrar centros médicos cercanos.\n\n¿En qué puedo ayudarte hoy?";
    options = ["Analizar una imagen de la piel", "Condiciones comunes", "Encontrar hospitales cercanos", "Consejos de seguridad solar"];
  } 
  // 2. HINDI LANGUAGE DETECTION (HI)
  else if (query.includes('नमस्ते') || query.includes('हेलो') || query.includes('मदद') || query.includes('बीमारी') || query.includes('इलाज')) {
    reply = "नमस्ते! मैं आपका **एआई स्किन डिजीज डिटेक्टर असिस्टेंट** हूँ, आपका वर्चुअल स्किन हेल्थ असिस्टेंट। 🩺\n\nमैं त्वचा की समस्याओं का विश्लेषण करने, त्वचा रोगों के लक्षणों को समझने, या आपके नजदीकी अस्पतालों को खोजने में आपकी मदद कर सकता हूँ।\n\nआज मैं आपकी क्या सहायता कर सकता हूँ?";
    options = ["त्वचा की जांच करें", "आम त्वचा रोग", "नजदीकी अस्पताल खोजें", "स्किन सेफ्टी टिप्स"];
  }
  // 3. FRENCH LANGUAGE DETECTION (FR)
  else if (query.includes('bonjour') || query.includes('salut') || query.includes('aide') || query.includes('symptome')) {
    reply = "Bonjour! Je suis votre **AI Skin Disease Detector Assistant**, votre assistant virtuel en dermatologie. 🩺\n\nJe peux vous aider à analyser les problèmes de peau, à comprendre les symptômes des affections cutanées ou à trouver des hôpitaux d'urgence à proximité.\n\nComment puis-je vous aider aujourd'hui?";
    options = ["Analyser une image de peau", "Maladies courantes", "Trouver des hôpitaux", "Conseils de sécurité cutanée"];
  }
  // 4. ENGLISH STANDARDS & NATURAL DIALOG MATRIX
  else if (query.includes('hello') || query.includes('hi ') || query.includes('hey') || query.includes('start') || query.includes('welcome')) {
    reply = "Hello! I am your **AI Skin Disease Detector Assistant**, your virtual dermatology assistant. 🩺\n\nI can help guide you through analyzing skin concerns, understanding symptoms of skin diseases, or finding emergency medical facilities near you.\n\nHow can I help you today?";
    options = ["Analyze a skin image", "Common skin conditions", "Find nearby hospitals", "General skin safety tips"];
  } else if (query.includes('analyze') || query.includes('upload') || query.includes('how to use') || query.includes('image') || query.includes('scan')) {
    reply = "To analyze a skin concern using our **AI Skin Diagnostic Engine**, follow these simple steps:\n\n1. Scroll to the **Skin Diagnostic Hub** section above.\n2. Click the upload container or drag-and-drop a close-up, high-quality image of the affected skin area.\n3. Verify your image is clear and well-lit, then click the **Analyze Skin Condition** button.\n4. Wait 1.5 seconds for our deep learning simulator to run feature extraction, after which a fully responsive medical report card will be rendered directly onto your dashboard!";
    options = ["Tell me about Eczema", "View nearby hospitals", "General skin safety tips"];
  } else if (query.includes('hospital') || query.includes('clinic') || query.includes('nearby') || query.includes('map') || query.includes('doctor') || query.includes('emergency')) {
    reply = "If you have an urgent skin flare-up or need an immediate medical consultation, look at our **Interactive Healthcare Locator** map section.\n\nIt detects your location automatically and renders active hospitals, 24/7 skin clinics, and emergency centers. Click on any facility card to inspect ratings, contact numbers, and get simulated live directions immediately!";
    options = ["Find skin clinics", "What is Melanoma?", "Analyze a skin image"];
  } else if (query.includes('melanoma') || query.includes('cancer')) {
    reply = "**Melanoma** is the most serious type of skin cancer, developing in cells called melanocytes that produce melanin.\n\n**Warning signs (The ABCDEs):**\n• **A - Asymmetry**: One half of the mole does not match the other.\n• **B - Border**: The edges are irregular, ragged, or blurred.\n• **C - Color**: The color is not uniform, containing various shades.\n• **D - Diameter**: Larger than 6mm (pencil eraser size).\n• **E - Evolving**: The mole changes size, shape, or color.\n\n*⚠️ Warning: Melanoma is highly treatable if caught early, but requires urgent medical attention. Consult a dermatologist immediately if you notice changes!*";
    options = ["Analyze a skin image", "General skin safety tips", "Find nearby hospitals"];
  } else if (query.includes('eczema') || query.includes('itch') || query.includes('dermatitis')) {
    reply = "**Atopic Dermatitis (Eczema)** is a common, non-contagious skin condition that causes dry, red, itchy, and inflamed skin patches.\n\n**Primary triggers:**\n• Stress and climate swings (cold/dry weather).\n• Aggressive soaps, fragrances, and detergents.\n• Food allergens or dust mites.\n\n**Best care routines:**\n• Moisturize multiple times daily with ceramide-rich creams.\n• Avoid scratching (it compromises the skin barrier further).\n• Bathe with lukewarm water using fragrance-free, mild cleansers.";
    options = ["Analyze a skin image", "Find skin clinics", "General skin safety tips"];
  } else if (query.includes('acne') || query.includes('pimple') || query.includes('zit')) {
    reply = "**Acne Vulgaris** occurs when hair follicles become plugged with sebum (oil) and dead skin cells, causing whiteheads, blackheads, or inflamed pustules.\n\n**Best practices:**\n• Wash your face twice daily with a gentle salicylic acid or benzoyl peroxide cleanser.\n• Do not squeeze or pick at pimples to prevent scarring and infection.\n• Apply lightweight, non-comedogenic (oil-free) sunscreens and moisturizers.\n\nFor deep cystic acne, a dermatologist may prescribe topical retinoids or oral therapies.";
    options = ["General skin safety tips", "Common skin conditions", "Analyze a skin image"];
  } else if (query.includes('sun') || query.includes('safety') || query.includes('tip') || query.includes('protect') || query.includes('prevention')) {
    reply = "Here are key clinical **Skin Safety Tips** to prevent damage and reduce skin cancer risk:\n\n1. **Always wear sunscreen**: Apply SPF 30+ broad-spectrum sunscreen daily, even during winter or overcast skies.\n2. **Reapply frequently**: Reapply every 2 hours when swimming or sweating outdoors.\n3. **Seek shade**: Keep out of direct sun during peak hours (10 AM to 4 PM).\n4. **Wear protective clothing**: Wide-brimmed hats, UV sunglasses, and tightly-woven long sleeves offer excellent protection.\n5. **Perform regular self-exams**: Inspect your skin once a month for new or changing moles.";
    options = ["Analyze a skin image", "What is Melanoma?", "Common skin conditions"];
  } else if (query.includes('common') || query.includes('disease') || query.includes('conditions') || query.includes('list')) {
    reply = "Our AI Diagnostic Engine can detect and provide detailed clinical breakdowns for these conditions:\n\n• **Melanoma (Malignant)** - Urgent skin cancer concern.\n• **Atopic Dermatitis (Eczema)** - Chronic itchy dry patches.\n• **Psoriasis Plaque** - Silvery scaly patches.\n• **Acne Vulgaris** - Clogged sebum-rich pores.\n• **Ringworm (Tinea Corporis)** - Ring-shaped fungal infections.\n• **Contact Dermatitis** - Localized allergic/irritant rash.\n• **Vitiligo** - Loss of melanin causing depigmented patches.\n• **Healthy Skin Profile** - Smooth and balanced tissue.\n\nSelect a condition from the buttons below or upload an image to start scanning!";
    options = ["What is Melanoma?", "Tell me about Eczema", "Analyze a skin image", "Find nearby hospitals"];
  } else {
    reply = "Thank you for asking! I've registered your question. \n\nRemember, while our **AI Skin Disease Detector** models provide highly accurate information on symptoms and clinical conditions, **this tool does not replace professional medical diagnosis or counseling**.\n\nIf you are experiencing severe itching, sudden mole alterations, bleeding, or localized pain, I highly recommend scheduling a consultation with a board-certified dermatologist.";
    options = ["Common skin conditions", "Find nearby hospitals", "Analyze a skin image", "General skin safety tips"];
  }

  res.json({
    reply,
    options,
    disclaimer: "Disclaimer: AI Skin Disease Detector Assistant is an education-focused assistant. Always consult a licensed medical professional for formal diagnoses."
  });
});

// Geo-Simulated Hospitals/Clinics Route
app.get('/api/hospitals', (req, res) => {
  const { lat, lng } = req.query;

  // Mock clinics and hospitals list
  const clinics = [
    {
      id: 'clinic-1',
      name: 'DermaCare Skin & Laser Clinic',
      type: 'Skin Clinic',
      rating: 4.9,
      reviewsCount: 182,
      latOffset: 0.008,
      lngOffset: -0.012,
      phone: '+1 (555) 387-6227',
      address: 'Suite 400, Medical Plaza, Broadway',
      hours: '24/7 Assistance Available',
      emergency: true,
      services: ['Melanoma screening', 'Eczema light therapy', 'Cystic acne treatments']
    },
    {
      id: 'clinic-2',
      name: 'Metro Dermatology Specialists',
      type: 'Skin Clinic',
      rating: 4.8,
      reviewsCount: 94,
      latOffset: -0.015,
      lngOffset: 0.018,
      phone: '+1 (555) 728-1994',
      address: '227 Health Ave, Science District',
      hours: '08:00 AM - 10:00 PM',
      emergency: false,
      services: ['Psoriasis clinical care', 'Fungal screening', 'Pediatric dermatology']
    },
    {
      id: 'hospital-3',
      name: 'St. Jude General Hospital & Emergency',
      type: 'General Hospital',
      rating: 4.6,
      reviewsCount: 420,
      latOffset: -0.005,
      lngOffset: -0.005,
      phone: '+1 (555) 911-4000',
      address: '900 Emergency Rd (Main Entrance)',
      hours: 'Open 24/7 (Emergency ER)',
      emergency: true,
      services: ['24/7 Trauma Care', 'Emergency Skin Burn treatments', 'Acute allergic rashes']
    },
    {
      id: 'clinic-4',
      name: 'Radiant Skin & Aesthetics Center',
      type: 'Skin Clinic',
      rating: 4.7,
      reviewsCount: 68,
      latOffset: 0.014,
      lngOffset: 0.011,
      phone: '+1 (555) 123-9090',
      address: '77 Wellness Blvd, Crestview',
      hours: '09:00 AM - 06:00 PM',
      emergency: false,
      services: ['Vitiligo pigment cover', 'Acne laser therapy', 'Cosmetic dermatology']
    },
    {
      id: 'hospital-5',
      name: 'City Urgent Care & Healthcare Hub',
      type: 'Emergency Care',
      rating: 4.5,
      reviewsCount: 153,
      latOffset: 0.002,
      lngOffset: 0.019,
      phone: '+1 (555) 888-2477',
      address: '50 Main St, Downtown Square',
      hours: 'Open 24/7 (Walk-ins welcome)',
      emergency: true,
      services: ['Acute rash diagnosis', 'Infection management', 'Dermatology consultation']
    }
  ];

  // Base coordinates defaults to London if geolocation is not shared
  const baseLat = parseFloat(lat) || 51.5074;
  const baseLng = parseFloat(lng) || -0.1278;

  // Reposition clinics relative to user coordinates dynamically to simulate accurate localization
  const localizedClinics = clinics.map(c => {
    return {
      ...c,
      lat: baseLat + c.latOffset,
      lng: baseLng + c.lngOffset
    };
  });

  res.json({
    baseLocation: { lat: baseLat, lng: baseLng },
    clinics: localizedClinics
  });
});

// Start backend server
async function startServer() {
  await db.connectDB();
  app.listen(PORT, () => {
    console.log(`\n=============================================================`);
    console.log(`AI Skin Disease Detector Advanced Clinical Server is actively running on port ${PORT}`);
    console.log(`Launch website at: http://localhost:${PORT}`);
    console.log(`=============================================================\n`);
  });
}

startServer();
