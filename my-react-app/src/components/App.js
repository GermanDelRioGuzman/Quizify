// src/components/App.js
import React from 'react';
import Navbar from './Navbar';
import Hero from './Hero';
import '../styles/App.css';

function App() {
  return (
    <div className="App">
      <Navbar />
      <Hero />
    </div>
  );
}

export default App;
