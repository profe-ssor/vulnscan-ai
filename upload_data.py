import os
from huggingface_hub import HfApi

api = HfApi()

# Safely retrieve the token from your environment variables
token = os.getenv("HF_TOKEN")

# Quick safety check to make sure the token was loaded properly
if token is None:
    raise ValueError("⚠️ HF_TOKEN environment variable not found! Please set it in your terminal before running.")

# Your destination dataset
dataset_name = "jederhion/vulnscan-ai-data" 

print("Uploading ChromaDB...")
api.upload_folder(
    folder_path="chroma_cve_db",
    repo_id=dataset_name,
    repo_type="dataset",
    path_in_repo="chroma_cve_db", # Keeps your folder structure intact
    token=token
)
print("Upload Complete!")