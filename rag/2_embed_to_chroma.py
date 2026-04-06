import os
import json
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

# ==========================================
# CONFIGURATION
# ==========================================
RAW_DATA_DIR = "./raw_knowledgebase"
DB_DIR = "./chroma_cve_db"
LOG_FILE = "./embedding_progress.log"

EMBEDDING_MODEL_NAME = "BAAI/bge-large-en-v1.5"
EMBEDDING_DEVICE = "cpu"

def get_processed_files():
    """Reads the log file to see which batches are already embedded."""
    if not os.path.exists(LOG_FILE):
        return set()
    with open(LOG_FILE, 'r') as f:
        return set(line.strip() for line in f)

def mark_file_processed(filename):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{filename}\n")

def process_and_embed():
    print(f"Loading {EMBEDDING_MODEL_NAME} Embedding Model...")
    embeddings = HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL_NAME,
        model_kwargs={'device': EMBEDDING_DEVICE}, 
        encode_kwargs={'normalize_embeddings': True}
    )
    
    db = Chroma(
        collection_name="cve_collection",
        embedding_function=embeddings,
        persist_directory=DB_DIR
    )
    
    if not os.path.exists(RAW_DATA_DIR):
        print(f"❌ Raw data directory {RAW_DATA_DIR} not found. Run the download script first.")
        return

    all_files = sorted([f for f in os.listdir(RAW_DATA_DIR) if f.endswith(".json")])
    processed_files = get_processed_files()
    pending_files = [f for f in all_files if f not in processed_files]
    
    if not pending_files:
        print("✅ All raw data files have been embedded!")
        return
        
    print(f"Found {len(pending_files)} pending batch files to embed.")

    for filename in pending_files:
        filepath = os.path.join(RAW_DATA_DIR, filename)
        print(f"\n🧠 Processing {filename}...")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                vulnerabilities = json.load(f)
                
            documents = []
            ids = []
            
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "Unknown ID")
                if cve_id == "Unknown ID": continue
                    
                desc_text = next((d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), "No description.")
                
                doc = Document(
                    page_content=f"{cve_id} - {desc_text}",
                    metadata={"source": "NVD", "cve_id": cve_id}
                )
                documents.append(doc)
                ids.append(cve_id)
                
            if documents:
                print(f"   -> Embedding and inserting {len(documents)} vectors into ChromaDB...")
                db.add_documents(documents=documents, ids=ids)
            
            # Log success so we don't re-embed this file if the script is restarted
            mark_file_processed(filename)
            
        except Exception as e:
            print(f"❌ Failed to process {filename}: {e}")
            print("Halting embedding process.")
            break

if __name__ == "__main__":
    process_and_embed()