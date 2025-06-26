import os
from supabase import create_client, Client

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    supabase.table("user").select("*").limit(1).execute()
    print("Connected to Supabase database.")
except Exception:
    print("Failed to connect to Supabase database.")
