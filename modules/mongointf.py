'''
This is a Python script for connecting to MongoDB.
Configuration parameters can be found in a separate configuration file, located in the 'conf' directory.
'''

# Import the necessary libraries
import pymongo
import os
import json


class MongoInterface:

    def connect_to_mongodb(self):
        # Get the configuration parameters from the configuration file
        config_path = os.path.join(os.path.dirname(__file__),"..", 'conf', 'config.json')
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Establish connection based on SSL configuration
        if not config["DATABASE_USE_SSL"] and config["DATABASE_AUTH_MECHANISM"] != 'MONGODB-X509':
            client = pymongo.MongoClient(
                config["DATABASE_ADDRESS"],
                username=config["DATABASE_USER"],
                password=config["DATABASE_PASSWORD"],
                authSource=config["DATABASE_NAME"],
                authMechanism=config["DATABASE_AUTH_MECHANISM"]
            )
        else:
            # Connect to MongoDB with SSL enabled
            client = pymongo.MongoClient(
                config["DATABASE_ADDRESS"],
                username=config["DATABASE_USER"],
                password=config["DATABASE_PASSWORD"],
                authSource=config["DATABASE_NAME"],
                tls=True,
                tlsCertificateKeyFile=config["DATABASE_TLS_CA_FILE"],
                authMechanism=config["DATABASE_AUTH_MECHANISM"]
            )

        return client


    def insert_document(self, collection_name, document):
        try:
            collection = self.db[collection_name]
            if isinstance(document, list):
                result = collection.insert_many(document)
            else:
                result = collection.insert_one(document)
            return result.inserted_ids if isinstance(document, list) else result.inserted_id
        except Exception as e:
            raise RuntimeError(f"Error inserting document(s) into {collection_name}: {e}")

    def find_documents(self, collection_name, query, projection=None):
        try:
            collection = self.db[collection_name]
            return list(collection.find(query, projection))
        except Exception as e:
            raise RuntimeError(f"Error finding documents in {collection_name}: {e}")
    
    def update_document(self, collection_name, query, update, upsert=False, multi=False):
        try:
            collection = self.db[collection_name]
            if multi:
                result = collection.update_many(query, update, upsert=upsert)
            else:
                result = collection.update_one(query, update, upsert=upsert)
            return result.modified_count
        except Exception as e:
            raise RuntimeError(f"Error updating document(s) in {collection_name}: {e}")

    def delete_documents(self, collection_name, query, multi=True):
        try:
            collection = self.db[collection_name]
            if multi:
                result = collection.delete_many(query)
            else:
                result = collection.delete_one(query)
            return result.deleted_count
        except Exception as e:
            raise RuntimeError(f"Error deleting document(s) in {collection_name}: {e}")

    def count_documents(self, collection_name, query={}):
        try:
            collection = self.db[collection_name]
            return collection.count_documents(query)
        except Exception as e:
            raise RuntimeError(f"Error counting documents in {collection_name}: {e}")


class DatabaseUtils:
    def switch_database(self, database_name):
        try:
            self.db = self.client[database_name]
        except Exception as e:
            raise RuntimeError(f"Error switching to database {database_name}: {e}")

    def list_collections(self):
        try:
            return self.db.list_collection_names()
        except Exception as e:
            raise RuntimeError(f"Error listing collections: {e}")

    
    def is_connected(self):
        try:
            self.client.admin.command('ping')
            return True
        except Exception as e:
            return False

    def close_connection(self):
        try:
            self.client.close()
        except Exception as e:
            raise RuntimeError(f"Error closing MongoDB connection: {e}")

    def create_index(self, collection_name, keys, unique=False):
        try:
            collection = self.db[collection_name]
            index_name = collection.create_index(keys, unique=unique)
            return index_name
        except Exception as e:
            raise RuntimeError(f"Error creating index on {collection_name}: {e}")




