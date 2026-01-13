import React from 'react';
import '../styles/global-loader.css';

const GlobalLoader = ({ size = "normal" }: { size?: "small" | "normal" | "large" }) => {
  const scale = size === "small" ? 0.5 : size === "large" ? 1.5 : 0.8;
  
  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div 
        className="orbit-loader-container" 
        style={{ transform: `scale(${scale})` }}
      >
        <div className="orbit-dot" />
        <div className="orbit-dot" />
        <div className="orbit-dot" />
      </div>
    </div>
  );
}

export default GlobalLoader;
