import { useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";

function Sign() {
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [verified, setVerified] = useState("");

  const handleMessageChange = (event) => {
    setMessage(event.target.value);
  };

  const handleSignMessage = async () => {
    try {
      const response = await axios.post("http://localhost:8080/sign", {
        message,
      });
      setSignature(response.data.signature);
    } catch (error) {
      console.error("Error during signing:", error);
      setSignature("Signing failed");
    }
  };

  const handleVerifyMessage = async () => {
    try {
      const response = await axios.post("http://localhost:8080/verify", {
        message,
        signature,
      });
      setVerified(response.data.verified ? "Verified" : "Not Verified");
    } catch (error) {
      console.error("Error during verification:", error);
      setVerified("Verification failed");
    }
  };

  return (
    <div className="app-container">
      <div className="menu-bar">
        <label htmlFor="algorithm-select">Choose Algorithm:</label>
        <select id="algorithm-select">
          <option value="RSA">RSA</option>
          <option value="ECC">ECC</option>
          <option value="ElGamal">ElGamal</option>
        </select>
        <Link to="/">
          <button>Encrypt</button>
        </Link>
      </div>

      <h1>Digital Signature</h1>

      <div className="container">
        <div className="message-area">
          <h3>Message</h3>
          <textarea
            title="message"
            placeholder="Enter your message to sign..."
            value={message}
            onChange={handleMessageChange}
          ></textarea>
        </div>

        <div className="button-container">
          <button className="action-button" onClick={handleSignMessage}>
            Sign Message
          </button>
        </div>

        <div className="signature-area">
          <h3>Signature</h3>
          <textarea
            title="signature"
            placeholder="Generated signature will appear here..."
            readOnly
            value={signature}
          ></textarea>
        </div>

        <div className="button-container">
          <button className="action-button" onClick={handleVerifyMessage}>
            Verify Signature
          </button>
        </div>

        <div className="verify-result">
          <h3>Verification Result</h3>
          <p>{verified}</p>
        </div>
      </div>
    </div>
  );
}

export default Sign;
