import React, { useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";

function Home() {
  const [algorithm, setAlgorithm] = useState("RSA");
  const [message, setMessage] = useState("");
  const [encryptedMessage, setEncryptedMessage] = useState("");
  const [decryptedMessage, setDecryptedMessage] = useState("");

  const handleAlgorithmChange = (event) => {
    setAlgorithm(event.target.value);
  };

  const handleMessageChange = (event) => {
    setMessage(event.target.value);
  };

  const handleEncryptedMessageChange = (event) => {
    setEncryptedMessage(event.target.value);
  };

  const handleEncrypt = async () => {
    try {
      const response = await axios.post("http://localhost:8080/encrypt", {
        algorithm,
        message,
      });
      setEncryptedMessage(response.data.encryptedMessage);
    } catch (error) {
      console.error("Error during encryption:", error);
      setEncryptedMessage("Encryption failed");
    }
  };

  const handleDecrypt = async () => {
    try {
      const response = await axios.post("http://localhost:8080/decrypt", {
        algorithm,
        encryptedMessage,
      });
      setDecryptedMessage(response.data.decryptedMessage);
    } catch (error) {
      console.error("Error during decryption:", error);
      setDecryptedMessage("Decryption failed");
    }
  };

  return (
    <div className="app-container">
      {/* Menu chọn thuật toán mã hóa */}
      <div className="menu-bar">
        <label htmlFor="algorithm-select">Choose Algorithm:</label>
        <select
          id="algorithm-select"
          value={algorithm}
          onChange={handleAlgorithmChange}
        >
          <option value="RSA">RSA</option>
          <option value="ECC">ECC</option>
          <option value="ElGamal">ElGamal</option>
        </select>
        <Link to="/sign">
          <button>Signature</button>
        </Link>
      </div>

      <h1>Cryptography Resources</h1>
      <div className="container">
        <div className="message-area">
          <h3>Message</h3>
          <textarea
            title="message"
            placeholder="Enter your message here..."
            value={message}
            onChange={handleMessageChange}
          ></textarea>
        </div>

        <div className="button-container">
          <button className="action-button" onClick={handleEncrypt}>
            Encrypt
          </button>
        </div>

        <div className="encrypt-area">
          <h3>Encrypted Message</h3>
          <textarea
            title="encrypt"
            placeholder="Encrypted text will appear here..."
            readOnly
            value={encryptedMessage}
          ></textarea>
        </div>

        <div className="decrypt-area">
          <h3>Decrypted Message</h3>
          <textarea
            title="decrypt"
            placeholder="Enter encrypted message for decryption..."
            value={encryptedMessage}
            onChange={handleEncryptedMessageChange}
          ></textarea>
        </div>

        <div className="button-container">
          <button className="action-button" onClick={handleDecrypt}>
            Decrypt
          </button>
        </div>

        <div className="decrypt-result">
          <h3>Decrypted Result</h3>
          <textarea
            title="decrypted"
            placeholder="Decrypted text will appear here..."
            readOnly
            value={decryptedMessage}
          ></textarea>
        </div>
      </div>
    </div>
  );
}

export default Home;
