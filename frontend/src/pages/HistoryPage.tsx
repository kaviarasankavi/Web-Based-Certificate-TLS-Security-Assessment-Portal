import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './HistoryPage.css';
import GradeBadge from '../components/GradeBadge';
import { listScans, deleteScan } from '../services/api';
import type { ScanResponse } from '../types';

export default function HistoryPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [gradeFilter, setGradeFilter] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await listScans({
        page,
        limit: 15,
        grade: gradeFilter || undefined,
        search: search || undefined,
      });
      setScans(res.scans);
      setTotal(res.total);
    } catch {
      // silent
    }
    setLoading(false);
  };

  const handleDelete = async (e: React.MouseEvent, scanId: string) => {
    e.stopPropagation();
    if (!confirm('Delete this scan? This cannot be undone.')) return;
    try {
      await deleteScan(scanId);
      setScans(prev => prev.filter(s => s.id !== scanId));
      setTotal(prev => prev - 1);
    } catch {
      alert('Failed to delete scan.');
    }
  };

  useEffect(() => {
    fetchScans();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, gradeFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchScans();
  };

  const totalPages = Math.ceil(total / 15);

  return (
    <div className="history-page container" id="history-page">
      <h1>Scan History</h1>
      <p className="history-subtitle">View and manage your previous TLS security assessments.</p>

      {/* Filters */}
      <div className="history-filters" id="history-filters">
        <form className="filter-search" onSubmit={handleSearch}>
          <input
            id="history-search-input"
            type="text"
            placeholder="Search by domain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button type="submit" className="btn btn-secondary">Search</button>
        </form>
        <select
          className="filter-select"
          value={gradeFilter}
          onChange={(e) => { setGradeFilter(e.target.value); setPage(1); }}
          id="grade-filter"
        >
          <option value="">All Grades</option>
          <option value="A+">A+</option>
          <option value="A">A</option>
          <option value="B">B</option>
          <option value="C">C</option>
          <option value="D">D</option>
          <option value="F">F</option>
        </select>
      </div>

      {/* Table */}
      {loading ? (
        <div className="loading-state"><div className="spinner"></div></div>
      ) : scans.length === 0 ? (
        <div className="empty-state glass-card">
          <p>No scans found. Start by scanning a domain!</p>
          <button className="btn btn-primary" onClick={() => navigate('/scan')}>Start Scanning</button>
        </div>
      ) : (
        <>
          <div className="history-table-wrap glass-card" id="history-table">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Date</th>
                  <th>Grade</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} onClick={() => navigate(`/scan?id=${scan.id}`)}
                    style={{ cursor: 'pointer' }}>
                    <td className="cell-domain">{scan.target_url}</td>
                    <td>{scan.created_at ? new Date(scan.created_at).toLocaleDateString() : 'N/A'}</td>
                    <td>{scan.grade ? <GradeBadge grade={scan.grade} size="sm" /> : '—'}</td>
                    <td>{scan.score !== null ? `${scan.score}/100` : '—'}</td>
                    <td><span className={`badge badge-${scan.status === 'completed' ? 'good' : scan.status === 'failed' ? 'critical' : 'info'}`}>{scan.status.toUpperCase()}</span></td>
                    <td className="cell-actions">
                      <button
                        className="btn btn-ghost btn-action"
                        title="View full results"
                        onClick={(e) => { e.stopPropagation(); navigate(`/scan?id=${scan.id}`); }}
                      >View →</button>
                      {scan.status === 'completed' && (
                        <button
                          className="btn btn-ghost btn-action btn-rescan"
                          title="Re-scan this domain"
                          onClick={(e) => { e.stopPropagation(); navigate(`/scan?url=${encodeURIComponent(scan.target_url)}`); }}
                        >↻ Rescan</button>
                      )}
                      <button
                        className="btn btn-ghost btn-action btn-delete"
                        title="Delete scan"
                        onClick={(e) => handleDelete(e, scan.id)}
                      >🗑</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="pagination" id="pagination">
              <button className="btn btn-ghost" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
              <span className="page-info">Page {page} of {totalPages}</span>
              <button className="btn btn-ghost" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
