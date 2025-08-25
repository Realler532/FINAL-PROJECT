import React, { useState, useEffect } from 'react';
import { Users, Plus, Edit, Trash2, Shield, Mail, Calendar, CheckCircle, XCircle } from 'lucide-react';
import { User, UserRole, CreateUserData } from '../types/user';
import { authService } from '../services/authService';

interface UserManagementProps {
  currentUser: User;
}

export function UserManagement({ currentUser }: UserManagementProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<UserRole[]>([]);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [createUserData, setCreateUserData] = useState<CreateUserData>({
    username: '',
    email: '',
    firstName: '',
    lastName: '',
    password: '',
    roleId: '',
    department: ''
  });

  useEffect(() => {
    loadUsers();
    loadRoles();
  }, []);

  const loadUsers = async () => {
    try {
      const fetchedUsers = await authService.getAllUsers();
      setUsers(fetchedUsers);
    } catch (error) {
      console.error('Failed to load users:', error);
      setUsers([]);
      setError('Failed to load users');
    }
  };

  const loadRoles = async () => {
    try {
      const fetchedRoles = await authService.getAllRoles();
      setRoles(fetchedRoles);
    } catch (error) {
      console.error('Failed to load roles:', error);
      setRoles([]);
      setError('Failed to load roles');
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    try {
      await authService.createUser(createUserData, currentUser.id);
      setSuccess('User created successfully');
      setCreateUserData({
        username: '',
        email: '',
        firstName: '',
        lastName: '',
        password: '',
        roleId: '',
        department: ''
      });
      setShowCreateForm(false);
      loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUpdateUserRole = async (userId: string, newRoleId: string) => {
    const newRole = roles.find(r => r.id === newRoleId);
    if (!newRole) return;

    try {
      await authService.updateUser(userId, { role: newRole });
      setSuccess('User role updated successfully');
      loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    }
  };

  const handleDeactivateUser = async (userId: string) => {
    if (!confirm('Are you sure you want to deactivate this user?')) return;

    try {
      await authService.deleteUser(userId);
      setSuccess('User deactivated successfully');
      loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to deactivate user');
    }
  };

  const getRoleColor = (roleLevel: number) => {
    switch (roleLevel) {
      case 1: return 'text-red-400 bg-red-900/30';
      case 2: return 'text-orange-400 bg-orange-900/30';
      case 3: return 'text-blue-400 bg-blue-900/30';
      case 4: return 'text-green-400 bg-green-900/30';
      default: return 'text-gray-400 bg-gray-900/30';
    }
  };

  const canManageUsers = authService.canManageUsers(currentUser);

  if (!canManageUsers) {
    return (
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="text-center py-8">
          <Shield className="h-12 w-12 text-red-400 mx-auto mb-3" />
          <h3 className="text-lg font-semibold text-white mb-2">Access Denied</h3>
          <p className="text-gray-400">You don't have permission to manage users.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white flex items-center">
            <Users className="h-6 w-6 text-blue-400 mr-2" />
            User Management
          </h2>
          <button
            onClick={() => setShowCreateForm(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center space-x-2"
          >
            <Plus className="h-4 w-4" />
            <span>Create User</span>
          </button>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-blue-400 text-2xl font-bold">{users.length}</div>
            <div className="text-gray-400 text-sm">Total Users</div>
          </div>
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-red-400 text-2xl font-bold">
              {users.filter(u => u.role.level === 1).length}
            </div>
            <div className="text-gray-400 text-sm">Administrators</div>
          </div>
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-orange-400 text-2xl font-bold">
              {users.filter(u => u.role.level === 2).length}
            </div>
            <div className="text-gray-400 text-sm">Managers</div>
          </div>
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-green-400 text-2xl font-bold">
              {users.filter(u => u.role.level >= 3).length}
            </div>
            <div className="text-gray-400 text-sm">Analysts & Viewers</div>
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="bg-red-900/30 border border-red-700/50 rounded-lg p-4 flex items-center space-x-2">
          <XCircle className="h-5 w-5 text-red-400" />
          <span className="text-red-300">{error}</span>
        </div>
      )}

      {success && (
        <div className="bg-green-900/30 border border-green-700/50 rounded-lg p-4 flex items-center space-x-2">
          <CheckCircle className="h-5 w-5 text-green-400" />
          <span className="text-green-300">{success}</span>
        </div>
      )}

      {/* Create User Form */}
      {showCreateForm && (
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">Create New User</h3>
          <form onSubmit={handleCreateUser} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
                <input
                  type="text"
                  value={createUserData.username}
                  onChange={(e) => setCreateUserData(prev => ({ ...prev, username: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Email</label>
                <input
                  type="email"
                  value={createUserData.email}
                  onChange={(e) => setCreateUserData(prev => ({ ...prev, email: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">First Name</label>
                <input
                  type="text"
                  value={createUserData.firstName}
                  onChange={(e) => setCreateUserData(prev => ({ ...prev, firstName: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Last Name</label>
                <input
                  type="text"
                  value={createUserData.lastName}
                  onChange={(e) => setCreateUserData(prev => ({ ...prev, lastName: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
                <input
                  type="password"
                  value={createUserData.password}
                  onChange={(e) => setCreateUserData(prev => ({ ...prev, password: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Department</label>
                <input
                  type="text"
                  value={createUserData.department}
                  onChange={(e) => setCreateUserData(prev => ({ ...prev, department: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Role</label>
              <select
                value={createUserData.roleId}
                onChange={(e) => setCreateUserData(prev => ({ ...prev, roleId: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                required
              >
                <option value="">Select a role</option>
                {roles.map(role => (
                  <option key={role.id} value={role.id}>{role.name}</option>
                ))}
              </select>
            </div>
            <div className="flex space-x-3">
              <button
                type="submit"
                disabled={isLoading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white rounded-lg font-medium transition-colors"
              >
                {isLoading ? 'Creating...' : 'Create User'}
              </button>
              <button
                type="button"
                onClick={() => setShowCreateForm(false)}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg font-medium transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Users List */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">All Users</h3>
        <div className="space-y-3">
          {users.map(user => (
            <div key={user.id} className="bg-gray-900 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center">
                    <span className="text-white font-medium">
                      {user.firstName[0]}{user.lastName[0]}
                    </span>
                  </div>
                  <div>
                    <div className="text-white font-medium">
                      {user.firstName} {user.lastName}
                    </div>
                    <div className="text-gray-400 text-sm flex items-center space-x-4">
                      <span>@{user.username}</span>
                      <span className="flex items-center">
                        <Mail className="h-3 w-3 mr-1" />
                        {user.email}
                      </span>
                      <span>{user.department}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getRoleColor(user.role.level)}`}>
                    {user.role.name}
                  </span>
                  {user.id !== currentUser.id && (
                    <>
                      <select
                        value={user.role.id}
                        onChange={(e) => handleUpdateUserRole(user.id, e.target.value)}
                        className="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                      >
                        {roles.map(role => (
                          <option key={role.id} value={role.id}>{role.name}</option>
                        ))}
                      </select>
                      <button
                        onClick={() => handleDeactivateUser(user.id)}
                        className="p-1 text-red-400 hover:text-red-300 transition-colors"
                        title="Deactivate user"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </>
                  )}
                </div>
              </div>
              {user.lastLogin && (
                <div className="mt-2 text-xs text-gray-500 flex items-center">
                  <Calendar className="h-3 w-3 mr-1" />
                  Last login: {user.lastLogin.toLocaleString()}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}