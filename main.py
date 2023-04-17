from typing import Annotated
from logging_conf import LogConfig
import logging
from logging.config import dictConfig
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import requests
from langchain.document_loaders import PyPDFLoader

from models import QueryVectorStore, CollectionName
from helpers import load_data, create_collection_qdrant, get_collection_qdrant, delete_collection_qdrant, query_vector_store_qdrant, create_vec_store_from_text
from helpers import init_cohere_client, init_qdrant_client, init_cohere_embeddings,add_texts_vector_store
from fastapi import Form

from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import dashboard
from supertokens_python import get_all_cors_headers
from supertokens_python import init, InputAppInfo, SupertokensConfig
from supertokens_python.recipe import passwordless, session

from supertokens_python.recipe.passwordless import ContactEmailOrPhoneConfig

from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.session import SessionContainer
from fastapi import Depends

from qdrant_client.http import models 


app = FastAPI()

headers = {
    'user-agent': "IndexAI/0.0.1",
    'Content-Type': "application/json",
    'Accept': "application/json",
}

init(
    app_info=InputAppInfo(
        app_name="licoricepizza",
        api_domain="https://licorice-backend.onrender.com",
        website_domain="https://licorice-frontend.onrender.com",
        api_base_path="/auth",
        website_base_path="/auth"
    ),
    supertokens_config=SupertokensConfig(
        # https://try.supertokens.com is for demo purposes. Replace this with the address of your core instance (sign up on supertokens.com), or self host a core.
        connection_uri="https://dev-90d7f2d1db0e11ed929a3966c2673b3c-us-east-1.aws.supertokens.io:3571",
        api_key="piDpBm86K25pfkOwT7gzMJxRbl4Ius"
    ),
    framework='fastapi',
    recipe_list=[
        dashboard.init(),
        session.init(), # initializes session features
        passwordless.init(
            flow_type="USER_INPUT_CODE",
            contact_config=ContactEmailOrPhoneConfig()
        ),
    ],
    mode='asgi' # use wsgi if you are running using gunicorn
)



# Logging
dictConfig(LogConfig().dict())
logger = logging.getLogger("indexai")

# CORS
origins = [

    "https://licorice-frontend.onrender.com",
    "https://licorice-backend.onrender.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["DELETE, POST, GET, PUT, OPTIONS"],
    allow_headers=['X-Custom-Header', 'Content-Type'] + get_all_cors_headers(),
)

app.add_middleware(get_middleware())


@app.get("/")
def read_r():
    return {"Hello": "World"}


@app.get("/api")
def read_root(session: SessionContainer = Depends(verify_session())):
    user_id = session.get_user_id()
    print(user_id)
    return {"Hello": "World"}


'''
Final function that is used to adding doc regardless of the collection_name existing or not
'''
@app.post("/api/add_docs")
async def add_docs(collection_name: Annotated[str,Form()], uploaded_file: UploadFile = File(...), session: SessionContainer = Depends(verify_session())):
    
    user_id = session.get_user_id()
    logger.info(f'user name {session.get_user_id()}')
    collection_name_modified = f'{user_id}_{collection_name}'

    newpath = f'./files/{user_id}'

    if not os.path.exists(newpath):
        os.makedirs(newpath)

    client_q = init_qdrant_client()
    cohere_client = init_cohere_client()

    file_location = f"./files/{user_id}/{uploaded_file.filename}"
    try:
        with open(file_location, "wb+") as file_object:
            file_object.write(uploaded_file.file.read())
        logger.info(f'successfully saved file {uploaded_file.filename}')
    except Exception as e:
        logger.info(f'error saving file {uploaded_file.filename}')
        return {"info": f"Error saving file {uploaded_file.filename}"}
    
    try:
        results = client_q.get_collection(collection_name=collection_name_modified)
        d = results.json()
        d2 = json.loads(d)
        if d2['status'] =='green':
            add_texts_vector_store(client_q = client_q,local_path_pdf=file_location, collection_name=collection_name)
            return {"info": f"Docs added to {collection_name_modified}"}
        
    except Exception as e:
        # there was no collection by this name
        logger.error(f"This exception happened: {e}")
        create_collection_qdrant(collection_name=collection_name, client_q=client_q)
        logger.info(f'created collection ..step 1')
        # create vector store from text
        # create_vec_store_from_text(local_path_pdf=file_location, collection_name=collection_name, embeddings=embeddings)
        add_texts_vector_store(client_q = client_q,local_path_pdf=file_location, collection_name=collection_name)
        logger.info(f'created vector store {collection_name} ..step 2')
        return {"info": f"Vec store {collection_name} created, and docs were added."}


    #     return {"info": f"Vec store {collection_name} created, and docs were added."}
    
    #check whether a collection exists

@app.post("/api/initalize_store")
async def initialize_vec_store(collection_name: Annotated[str,Form()], uploaded_file: UploadFile = File(...)):
    client_q = init_qdrant_client()
    cohere_client = init_cohere_client()

    # parse the files
    file_location = f"./files/{uploaded_file.filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(uploaded_file.file.read())
    logger.info(f'successfully saved file {uploaded_file.filename}')

    try:
        # create collection
        create_collection_qdrant(collection_name=collection_name, client_q=client_q)
        embeddings = init_cohere_embeddings()
        # create vector store from text
        create_vec_store_from_text(local_path_pdf=file_location, collection_name=collection_name,
                                   embeddings=embeddings)
        
        logger.info(f'created vector store {collection_name}')
        return {"info": f"Vec store {collection_name} created"}
    except Exception as e:
        return {"info": f"{e}"}



@app.post("/api/add_to_store")
async def add_texts_vec_store(collection_name: Annotated[str,Form()], uploaded_file: UploadFile = File(...)):
    
    # user_id = session.get_user_id()
    client_q = init_qdrant_client()
    cohere_client = init_cohere_client()

    # parse the files
    file_location = f"./files/{uploaded_file.filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(uploaded_file.file.read())
    logger.info(f'successfully saved file for  as {uploaded_file.filename}')

    try:
        # create collection
        embeddings = init_cohere_embeddings()
        # create vector store from text
        add_texts_vector_store(client_q = client_q,local_path_pdf=file_location, collection_name=collection_name)

        return {"info": f"Vec store {collection_name} fetched"}
    except Exception as e:
        return {"info": f"Collection doesnt exist"}




@app.post("/api/query_vec_store")
async def query_vec_store(body: QueryVectorStore):
    collection_name = body.collection_name
    query = body.query
    client_q = init_qdrant_client()
    cohere_client = init_cohere_client()
    try:
        # query vector store
        response = query_vector_store_qdrant(collection_name=collection_name, questions=[
                                             query], client_q=client_q, cohere_client=cohere_client)
        if response is None:
            return {"info": "Collection is incorrect/does not exist"}
        return response
    except Exception as e:
        logger.error(e)
        return {"error": e}

    # response = query_vector_store_qdrant(collection_name=collection_name, questions=[query], client_q=client_q, cohere_client=cohere_client)

@app.post("/api/upload_file")
async def upload_file(uploaded_file: UploadFile = File(...)):
    file_location = f"./files/{uploaded_file.filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(uploaded_file.file.read())
    return {"filename": uploaded_file.filename}
