/**
 * ScoreGauge — Animated SVG circular arc gauge for TLS security score.
 * Animates from 0 → score with easeOutCubic over 1.5s using rAF.
 */
import { useEffect, useRef, useState } from 'react';
import './ScoreGauge.css';

interface ScoreGaugeProps {
  score: number;
  grade: string;
}

function getColor(score: number): string {
  if (score >= 90) return '#00D4AA';
  if (score >= 80) return '#00B894';
  if (score >= 70) return '#74B9FF';
  if (score >= 60) return '#FDCB6E';
  if (score >= 50) return '#E17055';
  return '#FF6B6B';
}

function getGlowColor(score: number): string {
  if (score >= 90) return 'rgba(0, 212, 170, 0.5)';
  if (score >= 80) return 'rgba(0, 184, 148, 0.5)';
  if (score >= 70) return 'rgba(116, 185, 255, 0.5)';
  if (score >= 60) return 'rgba(253, 203, 110, 0.5)';
  if (score >= 50) return 'rgba(225, 112, 85, 0.5)';
  return 'rgba(255, 107, 107, 0.5)';
}

export default function ScoreGauge({ score, grade }: ScoreGaugeProps) {
  const radius = 78;
  const circumference = 2 * Math.PI * radius; // ≈ 489.84
  const arcLength = circumference * 0.75;      // 270° arc ≈ 367.38

  const color = getColor(score);
  const glowColor = getGlowColor(score);
  const targetOffset = (1 - score / 100) * arcLength;

  // Start fully hidden (offset = arcLength), animate to targetOffset
  const [currentOffset, setCurrentOffset] = useState(arcLength);
  const [displayScore, setDisplayScore] = useState(0);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    const duration = 1500;
    const startTime = Date.now();
    const startOffset = arcLength;

    // Small delay so the DOM is painted before animation starts
    const timer = setTimeout(() => {
      const tick = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // easeOutCubic for a smooth, spring-like deceleration
        const eased = 1 - Math.pow(1 - progress, 3);
        setCurrentOffset(startOffset + (targetOffset - startOffset) * eased);
        setDisplayScore(Math.round(eased * score));
        if (progress < 1) {
          rafRef.current = requestAnimationFrame(tick);
        }
      };
      rafRef.current = requestAnimationFrame(tick);
    }, 200);

    return () => {
      clearTimeout(timer);
      cancelAnimationFrame(rafRef.current);
    };
  }, [score, targetOffset, arcLength]);

  return (
    <div className="score-gauge" id="score-gauge">
      <svg viewBox="0 0 200 200" className="gauge-svg">
        {/* Outer glow ring */}
        <circle
          cx="100" cy="100" r={radius + 6}
          fill="none"
          stroke={glowColor}
          strokeWidth="1"
          opacity="0.4"
        />

        {/* Track arc (background) */}
        <circle
          cx="100" cy="100" r={radius}
          fill="none"
          stroke="rgba(26,42,74,0.9)"
          strokeWidth="14"
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset="0"
          strokeLinecap="round"
          transform="rotate(135 100 100)"
        />

        {/* Fill arc (animated) */}
        <circle
          cx="100" cy="100" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset={currentOffset}
          strokeLinecap="round"
          transform="rotate(135 100 100)"
          style={{
            filter: `drop-shadow(0 0 10px ${glowColor})`,
          }}
        />

        {/* Score number */}
        <text
          x="100" y="92"
          textAnchor="middle"
          className="gauge-score-num"
          fill={color}
        >
          {displayScore}
        </text>

        {/* "/ 100" label */}
        <text
          x="100" y="114"
          textAnchor="middle"
          className="gauge-divider-text"
          fill="rgba(139,149,165,0.75)"
        >
          out of 100
        </text>

        {/* Grade */}
        <text
          x="100" y="143"
          textAnchor="middle"
          className="gauge-grade-text"
          fill={color}
        >
          Grade {grade}
        </text>
      </svg>
      <p className="gauge-label">Security Score</p>
    </div>
  );
}
