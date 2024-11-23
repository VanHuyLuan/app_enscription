import React, { useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import crypto from "crypto-js";

function Sign() {
  const [input, setInput] = useState("");
  const [signature, setSignature] = useState("");
  const [hashInput, setHashInput] = useState("");
  const [verification, setVerification] = useState("");
  const [algorithm, setAlgorithm] = useState("RSA");
  const [hashedMessage, setHashedMessage] = useState(""); // Dùng để lưu hash của input bên người gửi
  const [hashedHashInput, setHashedHashInput] = useState(""); // Dùng để lưu hash của input bên người nhận

  // Hàm tạo chữ ký số sử dụng API backend
  const signMessage = async () => {
    try {
      // Tạo hash cho đầu vào bên người gửi
      const hash = crypto.SHA256(input).toString();
      setHashedMessage(hash);

      const response = await axios.post("http://localhost:8080/sign", {
        message: hash,
        algorithm: algorithm,
      });

      setSignature(response.data.signature || "Lỗi khi tạo chữ ký");
    } catch (error) {
      console.error("Error signing message:", error);
      setSignature("Lỗi khi tạo chữ ký");
    }
  };

  // Hàm kiểm tra chữ ký số sử dụng API backend
  const verifySignature = async () => {
    try {
      // Tạo hash cho đầu vào bên người nhận
      const hash = crypto.SHA256(hashInput).toString();
      setHashedHashInput(hash);

      const response = await axios.post("http://localhost:8080/verify", {
        message: hash,
        signature: signature,
        algorithm: algorithm,
      });

      const isValid = response.data.isValid;
      setVerification(isValid ? "Chữ ký hợp lệ" : "Chữ ký không hợp lệ");
    } catch (error) {
      console.error("Error verifying signature:", error);
      setVerification("Lỗi khi kiểm tra chữ ký");
    }
  };

  return (
    <div className="app-container" style={{ maxWidth: "1400px" }}>
      <div className="menu-bar" style={{ paddingTop: "0px" }}>
        <label htmlFor="algorithm-select">Choose Algorithm:</label>
        <select
          id="algorithm-select"
          value={algorithm}
          onChange={(e) => setAlgorithm(e.target.value)}
        >
          <option value="RSA">RSA</option>
          <option value="ECC">ECC</option>
          <option value="ElGamal">ElGamal</option>
        </select>
        <Link to="/">
          <button className="btn-tran">Encrypt</button>
        </Link>
      </div>
      <h1>Digital Signature</h1>
      <div style={{ display: "flex", gap: "20px" }}>
        {/* Người Gửi */}
        <div
          style={{
            backgroundColor: "#d4edda",
            padding: "20px",
            flex: 1,
            paddingRight: "40px",
            borderRadius: "10px",
          }}
        >
          <div style={{ textAlign: "center" }}>
            <h2>📤 Người Gửi</h2>
          </div>
          <input
            type="text"
            placeholder="Đầu vào"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            style={{ width: "100%", marginBottom: "10px", height: "30px" }}
          />
          <div className="button-container">
            <button className="sign-button" onClick={signMessage}>
              Tạo chữ ký
            </button>
          </div>
          <div>
            <h4>Hash của đầu vào:</h4>
            <textarea
              value={hashedMessage}
              readOnly
              rows={3}
              style={{ width: "100%" }}
            ></textarea>
          </div>
          <div>
            <h4>Chữ ký được tạo:</h4>
            <textarea
              value={signature}
              readOnly
              rows={5}
              style={{ width: "100%" }}
            ></textarea>
          </div>
        </div>

        {/* Người Nhận */}
        <div
          style={{
            backgroundColor: "#cce5ff",
            padding: "20px",
            flex: 1,
            paddingRight: "40px",
            borderRadius: "10px",
          }}
        >
          <div style={{ textAlign: "center" }}>
            <h2>📥 Người nhận</h2>
          </div>
          <input
            type="text"
            placeholder="Đầu vào"
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            style={{ width: "100%", marginBottom: "10px", height: "30px" }}
          />
          <div className="button-container">
            <button className="sign-button" onClick={verifySignature}>
              Kiểm tra
            </button>
          </div>

          <div>
            <h4>Hash của đầu vào:</h4>
            <textarea
              value={hashedHashInput}
              readOnly
              rows={3}
              style={{ width: "100%" }}
            ></textarea>
          </div>

          <div>
            <h4>Kết quả kiểm tra:</h4>
            <textarea
              value={verification}
              readOnly
              rows={2}
              style={{ width: "100%" }}
            ></textarea>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Sign;
