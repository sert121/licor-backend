
# import basemodel from pydantic
from pydantic import BaseModel

# create pydantic models for langch



class QueryVectorStore(BaseModel):
    query:str
    collection_name:str

class CollectionName(BaseModel):
    collection_name:str

class Code(BaseModel):
    code:str
