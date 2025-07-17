import os
from supabase import create_client, Client

SUPABASE_URL = "https://qqcpxswuauisvluwyxxa.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFxY3B4c3d1YXVpc3ZsdXd5eHhhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTA4MTk4MzQsImV4cCI6MjA2NjM5NTgzNH0.0X9bJOe7mQ2WxaEChOly9iwP-rjFx6Dolb9WkoO_ZD0"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    supabase.table("user").select("*").limit(1).execute()
    print("Connected to Supabase database.")
except Exception:
    print("Failed to connect to Supabase database.")
