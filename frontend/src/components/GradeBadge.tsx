import './GradeBadge.css';

interface GradeBadgeProps {
  grade: string;
  size?: 'sm' | 'md' | 'lg';
}

const gradeColorMap: Record<string, string> = {
  'A+': 'grade-a-plus',
  'A': 'grade-a',
  'B': 'grade-b',
  'C': 'grade-c',
  'D': 'grade-d',
  'F': 'grade-f',
};

export default function GradeBadge({ grade, size = 'md' }: GradeBadgeProps) {
  const colorClass = gradeColorMap[grade] || 'grade-f';
  return (
    <div className={`grade-badge ${colorClass} grade-${size}`} id={`grade-badge-${grade}`}>
      {grade}
    </div>
  );
}
