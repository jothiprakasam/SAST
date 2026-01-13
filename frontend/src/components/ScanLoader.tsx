import React from 'react';
import '../styles/loader.css';

const ScanLoader = ({ text = "ANALYZING" }: { text?: string }) => {
  return (
    <div className="flex flex-col items-center justify-center p-8">
      <div className="scanner-loader-wrapper relative">
        <p className="loader text-5xl font-extrabold tracking-wider uppercase text-transparent bg-clip-text bg-gradient-to-b from-white to-gray-500">
           <span>{text}</span>
        </p>
      </div>
      <p className="mt-8 text-[#9197b3] text-sm animate-pulse tracking-widest uppercase">
          Processing Code Structure
      </p>
    </div>
  );
}

export default ScanLoader;
