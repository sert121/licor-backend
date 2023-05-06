from pprint import pprint
import requests
import os
from langchain.document_loaders import NotionDBLoader



from logging.config import dictConfig
import logging
from logging_conf import LogConfig

# Logging
dictConfig(LogConfig().dict())
logger = logging.getLogger("indexai")


# DATABASE_ID = "your_database_id"
# load dotenv
from dotenv import load_dotenv
load_dotenv()
NOTION_API_KEY = os.getenv("NOTION_API_KEY")

def get_subpage_data(page_id, NOTION_API_KEY=NOTION_API_KEY):
    try:
        subpage_url = f"https://api.notion.com/v1/blocks/{page_id}/children"
        headers = {
            "Notion-Version": "2021-08-16",
            "Authorization": f"Bearer {NOTION_API_KEY}",
            "Content-Type": "application/json",
        }
        response = requests.get(subpage_url, headers=headers)
        response_data = response.json()
        if response.status_code != 200:
            raise Exception(response_data["message"])
        subpage_data = ""
        for block in response_data["results"]:
            if block["type"] == "paragraph":
                subpage_data += block["paragraph"]["text"][0]["text"]["content"]
    except Exception as e:
        # print("block---",block)
        # print(e)
        subpage_data = ""
    return subpage_data


def fetch_all_subpages_data(DATABASE_ID: str):
    database_url = f"https://api.notion.com/v1/databases/{DATABASE_ID}/query"
    headers = {
        "Notion-Version": "2021-08-16",
        "Authorization": f"Bearer {NOTION_API_KEY}",
        "Content-Type": "application/json",
    }
    response = requests.post(database_url, headers=headers)
    response_data = response.json()
    if response.status_code != 200:
        raise Exception(response_data["message"])
    for result in response_data["results"]:
        page_id = result["id"]
        subpage_data = get_subpage_data(page_id)
        pprint(subpage_data)


def fetch_shared_subpages(object_type:str='database', NOTION_API_KEY:str=NOTION_API_KEY):
    shared_search = f"https://api.notion.com/v1/search"
    headers = {
        "Notion-Version": "2022-06-28",
        "Authorization": f"Bearer {NOTION_API_KEY}",
        "Content-Type": "application/json",
    }
    data = {
        "query": "",
        "filter": {
            "value": f"{object_type}",
            "property": "object"
        },
        "sort": {
            "direction": "ascending",
            "timestamp": "last_edited_time"
        }
    }

    response = requests.post(shared_search, headers=headers, json=data)
    data_response = response.json()
    database_ids,database_urls = [],[]
    try:
        for result in data_response["results"]:
            database_ids.append(result["id"])
            database_urls.append(result["url"])
    except KeyError:
        logger.info(f"Key Error, id {result['id']} not found")
    return database_ids, database_urls

def notion_db_loader_langchain(database_id:str):
    loader = NotionDBLoader(NOTION_API_KEY, database_id)
    docs = loader.load()
    for doc in docs[:2]:
        print(doc)
    
    return 1

if __name__ == "__main__":  
    database_ids = fetch_shared_subpages()
    print('The db id is : ', database_ids[0], '----\n')
    for db_id in database_ids[:1]:
        notion_db_loader_langchain(db_id)
    