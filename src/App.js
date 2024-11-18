import React from "react";
import { Routes, Route } from "react-router-dom";
import Home from "./Home";
import Sign from "./Sign";
import "./App.css";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/sign" element={<Sign />} />
    </Routes>
  );
}

export default App;
