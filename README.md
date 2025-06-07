# BitQuant Auto-Bot

This is a Python-based bot designed to automate chat interactions on the BitQuant platform to earn points. It is a conversion and modification of the original NodeJS script by NTExhaust.

## Features

* **Multi-Account Support**: Run the bot for multiple accounts sequentially.
* **Proxy Support**: Supports HTTP proxies to cycle through different IP addresses.
* **Customizable Messages**: Use a list of custom messages for the bot to send randomly.
* **Session Management**: Automatically handles login, token refreshes, and retries.
* **Scheduled Loop**: Automatically re-runs the process for all accounts every 24 hours.

---

## Prerequisites

* [Python](https://www.python.org/downloads/) (version 3.8 or newer)
* [Git](https://git-scm.com/downloads/)

---

## ⚙️ Setup & Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
    cd your-repo-name
    ```

2.  **Create a Virtual Environment**
    It is highly recommended to use a virtual environment to avoid conflicts with other projects.
    ```bash
    # Create the environment
    python -m venv venv
    ```
    ```bash
    # Activate the environment (Windows)
    .\venv\Scripts\activate
    ```
    ```bash
    # Activate the environment (macOS/Linux)
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    With your virtual environment activated, install the required Python libraries.
    ```bash
    pip install -r requirements.txt
    ```
---

## 📝 Configuration

Before running the bot, you need to create and configure the following `.txt` files in the main folder:

* **`PrivateKeys.txt`**
    * Add your Solana private keys to this file.
    * Place **one private key per line**.
    * **Warning**: This file is extremely sensitive. Never share it.

* **`command.txt`**
    * Add the chat messages you want the bot to send.
    * Place **one message per line**. The bot will pick one randomly for each chat.

* **`proxy.txt`** (Optional)
    * If you wish to use proxies, add them to this file.
    * The required format is `http://user:pass@host:port`.
    * Place **one proxy per line**.

---

## ▶️ How to Run

1.  Make sure your virtual environment is activated.
2.  Run the bot from your terminal:
    ```bash
    python bot.py
    ```
3.  The script will then prompt you to enter:
    * The number of chats to perform for each account.
    * Whether you want to use proxies (`y/n`).

---

## ⚠️ Security Warning

* **USE AT YOUR OWN RISK.** You are solely responsible for any actions performed by this bot and for the security of your accounts.
* It is **STRONGLY RECOMMENDED** to use new, empty "burner" wallets. Do not use wallets that contain significant assets.
* **NEVER SHARE YOUR PRIVATE KEYS** or the `PrivateKeys.txt` file with anyone.

## Credits

* This script is a Python conversion of the original NodeJS version created by **NTExhaust**.
* Adapted and maintained by **Airdropversity ID**.
