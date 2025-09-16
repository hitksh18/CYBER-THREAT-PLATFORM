# Cyber Threat Platform - Dev Run

1. Create and activate venv:
   python -m venv venv
   venv\Scripts\activate   # windows
   source venv/bin/activate

2. Install:
   pip install -r requirements.txt

3. Create environment variables:
   - MONGO_URI (default mongodb://127.0.0.1:27017)
   - OTX_API_KEY (optional)
   - AI_MODEL_PATH, AI_VECT_PATH (optional)

4. Start:
   uvicorn app:app --reload

5. Docs:
   http://127.0.0.1:8000/docs
