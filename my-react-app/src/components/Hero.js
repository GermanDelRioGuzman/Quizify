// src/components/Hero.js
import React from 'react';
import '../styles/Hero.css';

const Hero = () => {
  return (
    <div className="hero">
      <div className="hero-text">
        <h1>Crafting the Future</h1>
        <p>
          Elevate your spaces sustainably with Nilsson. Discover innovative modern designs for architecture, interior, and exterior that harmonize with nature.
        </p>
      </div>
      <div className="hero-image">
        <img src="/path/to/hero-image.jpg" alt="Building" />
      </div>
    </div>
  );
};

export default Hero;
