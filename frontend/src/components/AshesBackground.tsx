import React, { useEffect, useRef } from 'react';

const AshesBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = canvas.width = canvas.parentElement?.clientWidth || window.innerWidth;
    let height = canvas.height = canvas.parentElement?.clientHeight || window.innerHeight;

    const particles: Particle[] = [];
    const particleCount = 120; // Density of particles

    class Particle {
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;
      life: number;
      maxLife: number;
      opacity: number;
      fadeSpeed: number;

      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        // Subtle drift upwards and sideways like ash
        this.vx = (Math.random() - 0.5) * 0.5; 
        this.vy = -Math.random() * 0.8 - 0.2; 
        this.size = Math.random() * 2 + 0.5;
        this.maxLife = Math.random() * 200 + 100;
        this.life = Math.random() * this.maxLife;
        this.opacity = Math.random() * 0.5 + 0.2;
        this.fadeSpeed = Math.random() * 0.005 + 0.002;
      }

      update() {
        this.x += this.vx + Math.sin(this.y * 0.01) * 0.2; // Add sine wave drift
        this.y += this.vy;
        this.life--;

        // Fade out and in effect or just fade out at end of life
        if (this.life < 50) {
            this.opacity -= this.fadeSpeed * 2;
        }

        // Reset if out of bounds or dead
        if (this.life <= 0 || this.y < -10 || this.opacity <= 0) {
          this.reset();
        }
      }

      reset() {
        this.x = Math.random() * width;
        this.y = height + 10; // Start from bottom
        this.vx = (Math.random() - 0.5) * 0.5;
        this.vy = -Math.random() * 0.8 - 0.2;
        this.life = Math.random() * 200 + 100;
        this.opacity = Math.random() * 0.5 + 0.2;
      }

      draw(ctx: CanvasRenderingContext2D) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(200, 210, 230, ${this.opacity})`;
        ctx.fill();
      }
    }

    // Initialize particles
    for (let i = 0; i < particleCount; i++) {
        particles.push(new Particle());
    }

    let animationDetails = 0;
    const animate = () => {
        ctx.clearRect(0, 0, width, height);

        // Optional: Draw a very subtle gradient background if needed, but we rely on CSS for the main bg color
        // ctx.fillStyle = 'rgba(0,0,0,0.02)';
        // ctx.fillRect(0,0, width, height);

        particles.forEach(p => {
            p.update();
            p.draw(ctx);
        });
        
        animationDetails = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
        if (!canvas || !canvas.parentElement) return;
        width = canvas.width = canvas.parentElement.clientWidth;
        height = canvas.height = canvas.parentElement.clientHeight;
    };

    window.addEventListener('resize', handleResize);

    return () => {
        cancelAnimationFrame(animationDetails);
        window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <canvas 
        ref={canvasRef} 
        style={{ 
            position: 'absolute', 
            top: 0, 
            left: 0, 
            width: '100%', 
            height: '100%', 
            pointerEvents: 'none',
            zIndex: 0 
        }} 
    />
  );
};

export default AshesBackground;
