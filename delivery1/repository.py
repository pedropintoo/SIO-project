import os
from server.app import create_app

repository = create_app()

if __name__ == '__main__':
    repository.run(
        host=os.getenv("REPOSITORY_ADDRESS"), 
        port=os.getenv("REPOSITORY_PORT"), 
        debug=os.getenv("REPOSITORY_DEBUG")
    )
