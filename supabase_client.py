import os
from supabase import create_client, Client

# Access secrets from Replit's environment
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    supabase.table("user").select("*").limit(1).execute()
    print("Connected to Supabase database.")
except Exception as e:
    print("Failed to connect to Supabase database.")
    print(e)
