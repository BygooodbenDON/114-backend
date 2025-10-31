from typing import Annotated,List,Union
from fastapi import Cookie,FastAPI , Path ,Body,Form
from pydantic import BaseModel,Field

class Item(BaseModel):
    name:str
    description:str | None = Field(
        default=None,title="The description of the item",max_length=300
    )
    price: float=Field(gt=0, description="The price must be greater than zero")
    tax: Union[float,None]= None
    tag : List[str] =[]

app=FastAPI()

@app.post("/login")
async def login(
    username:Annotated[str,Form()],
    password:Annotated[str,Form()],
):
    return{"username":username}

@app.get("/")
async def root():
    return{"message":"Hello world"}



@app.get("/item/{item_id}")
async def read_item(item_id):
    return{"item_id":item_id}
'''
@app.get("/item/")
async def read_item(skip: int =0,limit: int =10):
    return fake_items_db[skip:skip+limit]

fake_items_db=[
    {"item_name":"Foo"},
    {"item_name":"Bar"},
    {"item_name":"Baz"}
]
'''
@app.get("/item/")
async def read_item(ads_id:Annotated[str | None,Cookie()])->list[Item]:
    return {"ads_id",ads_id}
@app.post("/item/")
async def create_item(item:Item)->Item:
    return item
'''
@app.post("/item/")
async def create_item(item:Item):
    item_dict=item.model_dump()
    if item.tax is not None:
        price_with_tax=item.price+item.tax
        item_dict.update({"price_with_tax":price_with_tax})
    return item_dict
'''
'''
@app.put("/item/{item_id}")
async def update_item(
    item_id: Annotated[int , Path(title="The ID of the item to get", ge=0 , le=1000)],
    q: str | None = None, 
    item : Item| None = None
    
):
    result = {"item_id":item_id}
    if q:
        result.update({"q":q})
    if item:
        result.update({"item":item})
    return result
'''
@app.put("/item/{item_id}")
async def update_item(item_id:int,item:Annotated[Item, Body(embed=True)]):
     result = {"item_id":item_id,"item":item}
     return result