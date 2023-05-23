def query_vector_store_qdrant(collection_name:str, questions:list, client_q: QdrantClient, cohere_client: cohere.Client):

    # double check if collection exists
    try:
        details = get_collection_qdrant(collection_name=collection_name,client_q=client_q)
    except:
        logger.error('collection does not exist, try creating collection by querying the initialize endpoint')
        return None


    embedded_vectors = cohere_client.embed(model="large",
                                           texts=questions).embeddings
    # Conversion to float is required for Qdrant
    vectors = [list(map(float, vector)) for vector in embedded_vectors]
    k_max = 15

    response = client_q.search(collection_name=f"{collection_name}",
                               query_vector=vectors[0],
                               limit=k_max,
                               with_payload=True)
    summarized_responses = {'result':[]}

    for i in range(len(response)):
        # logger.info(f"#{i} {response[i].payload['page_content']}")
        page_content = response[i].payload['page_content']
        try: 
            url = response[i].payload['metadata']['url']
            content_type = response[i].payload['metadata']['type']
        except:
            url = ''
            content_type = ''
        # try:
        #     # summary = cohere_client.summarize(text=page_content)
        #     if i == 0:
        #         messages = [
        #         {"role": "system", "content": "You are a helpful assistant who is excellent at summarizing content of different types. Make sure you retain the most relevant details while summarizing."},
        #         {"role": "user", "content": f"Summarize this text for me. Text: {page_content[:700]}"}
        #         ]
        #         # prompt = '''Generate a summary for the following text.
        #         # TEXT: {page_content}
        #         # SUMMARY:
        #         # '''

        #         response_openai = openai.ChatCompletion.create(
        #         model="gpt-3.5-turbo", messages=messages, max_tokens=800)

        #         reply = response_openai['choices'][0]['message']['content']
        #     else:
        #         # reply is the same as text completion
        #         reply = page_content

        #     # logger.info(f"summary: {reply}")

        #     # summarized_responses['result'][i]['summary'] = reply
        #     # summarized_responses['result'][i]['page_content'] = page_content
        #     # logger.info(f"summary: {reply}")
        #     # logger.info(f"summary: {summary}")
        # except Exception as exception:
        #     logger.error(exception)

            # summary = None
        # d = {'summary':summary.summary,'page_content':page_content} 
        d = {'summary':page_content[:100],'type':content_type,'url':url,'page_content':page_content}
        summarized_responses['result'].append(d)
        
    return summarized_responses
    
    # for result_item  in response[:1]:
    #     metadata = result_item['payload']['metadata']
    #     page_content = result_item['payload']['page_content']
    #     # take the page_content and summarize it using cohere
    #     summary = cohere_client.summarize(model="large",text=page_content)
    #     summarized_responses["response"].append(summary)
    
    # return summarized_responses
    
    # print('------\n', response[0].payload['page_content'], '\n------')
    # return response
    
def add_notion_docs(auth_token,collection_name='default_notion'):

    client_q = init_qdrant_client()
    try:
        client_q.get_collection(
        collection_name=f"{collection_name}"
    )
    except Exception as exception:
        client_q.recreate_collection(
            collection_name=f"{collection_name}",
            vectors_config=models.VectorParams(size=4096,
                                            distance=models.Distance.COSINE),
        )

    try:
        embeddings = init_cohere_embeddings()
        store = Qdrant(client=client_q,
                        embedding_function=embeddings.embed_query,
                        collection_name=collection_name)
        
        list_pages, page_urls = fetch_shared_subpages(object_type='page',NOTION_API_KEY=auth_token)
    except Exception  as e:
        logger.error(e, 'fetching issue')
    
    try:
        # print(list_pages)
        counter = 0
        for i  in range(len(list_pages[:])):
            data = get_subpage_data(page_id = list_pages[i],NOTION_API_KEY=auth_token)
            if data!="":
            # logger.info("successfully fetched data subpages")
                store.add_texts(texts = [data], metadatas=[{'type':'notion','url':page_urls[i], 'page_id':list_pages[i]}])
 
    except Exception as exception:
        # logger.info(exception)
        print(exception)