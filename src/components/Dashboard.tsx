import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { API_URL } from '../config';
import { Shield, ShieldAlert, Globe } from 'lucide-react';

interface AccessRule {
  id: number;
  port: number;
  protocol: string;
  status: string;
}

export default function Dashboard() {
  const { user } = useAuth();
  const [accessRules, setAccessRules] = useState<AccessRule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAccessRules();
  }, []);

  async function fetchAccessRules() {
    try {
      const response = await fetch(`${API_URL}/api/access-rules`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setAccessRules(data);
      }
    } catch (error) {
      console.error('Error fetching access rules:', error);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center space-x-4 mb-8">
          <div className="bg-blue-100 p-3 rounded-full">
            <Globe className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h2 className="text-2xl font-bold">Welcome, {user?.name}</h2>
            <p className="text-gray-600">Your access control dashboard</p>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-gray-50 p-4 rounded-lg">
            <h3 className="text-lg font-semibold mb-4">Your Access Rules</h3>
            <div className="grid gap-4">
              {accessRules.map((rule) => (
                <div
                  key={rule.id}
                  className="bg-white p-4 rounded-lg border border-gray-200 flex items-center justify-between"
                >
                  <div className="flex items-center space-x-4">
                    {rule.status === 'active' ? (
                      <Shield className="w-5 h-5 text-green-500" />
                    ) : (
                      <ShieldAlert className="w-5 h-5 text-red-500" />
                    )}
                    <div>
                      <p className="font-medium">
                        Port {rule.port} ({rule.protocol})
                      </p>
                      <p className="text-sm text-gray-500">
                        Status: {rule.status === 'active' ? 'Active' : 'Inactive'}
                      </p>
                    </div>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-sm font-medium ${
                      rule.status === 'active'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    {rule.status === 'active' ? 'Allowed' : 'Blocked'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}