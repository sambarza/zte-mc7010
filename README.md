# ZTE MC7010 Script

Some time exploring ZTE MC7010...

This script provides an interface to interact with the ZTE MC7010 router. It includes functions to:
- Login to the router
- Retrieve the active band
- Perform a speed-up operation

## Usage

1. Ensure you have `config.json` with the following structure:
    ```json
    {
        "host": "your_router_ip",
        "password": "your_password"
    }
    ```

2. Run the script:
    ```bash
    python zte_mc7010.py
    ```