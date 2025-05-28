import sqlite3
import pickle
import numpy as np
import os
from openai import OpenAI

DB_PATH = 'examples.db'
EMBEDDING_MODEL = 'text-embedding-3-small'

desc = input("Enter description: ")
cmd = input("Enter ffuf command: ")

api_key = os.getenv("OPENROUTER_API_KEY")
client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

embedding = client.embeddings.create(model=EMBEDDING_MODEL, input=desc).data[0].embedding
emb_blob = pickle.dumps(np.array(embedding, dtype='float32'))

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("INSERT INTO examples (description, command, embedding) VALUES (?, ?, ?)", (desc, cmd, emb_blob))
conn.commit()
conn.close()

print("✅ Example added.")
