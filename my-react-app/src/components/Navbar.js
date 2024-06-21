import React from 'react'; 
import '../styles/Navbar.css'

const Navbar = () => {
    return (
      <nav className="navbar">
        <div className="navbar-logo">
          <img src="/path/to/logo.png" alt="Logo" />
        </div>
        <ul className="navbar-links">
          <li>Projects</li>
          <li>About</li>
          <li>Contact</li>
        </ul>
      </nav>
    );
};

export default Navbar; 