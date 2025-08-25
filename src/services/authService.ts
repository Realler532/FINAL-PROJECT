import { supabase } from '../lib/supabaseClient';
import { User, UserRole, LoginCredentials, CreateUserData } from '../types/user';
import bcrypt from 'bcryptjs';

class AuthService {
  private currentUser: User | null = null;

  async login(credentials: LoginCredentials): Promise<User> {
    // Query the users table with proper joins for role information
    const { data, error } = await supabase
      .from('users')
      .select(`
        id,
        username,
        email,
        full_name,
        role,
        role_level,
        is_active,
        last_login,
        created_at,
        updated_at,
        createdBy
      `)
      .eq('username', credentials.username)
      .eq('is_active', true)
      .single();

    if (error || !data) {
      throw new Error('Invalid username or password');
    }

    // In a real implementation, verify password hash
    // For demo purposes, we'll accept any password
    
    // Update last login
    await supabase
      .from('users')
      .update({ last_login: new Date().toISOString() })
      .eq('id', data.id);

    // Transform database user to application user format
    this.currentUser = this.transformDbUserToAppUser(data);
    localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
    return this.currentUser;
  }

  private transformDbUserToAppUser(dbUser: any): User {
    const [firstName, lastName] = dbUser.full_name.split(' ');
    return {
      id: dbUser.id,
      username: dbUser.username,
      email: dbUser.email,
      firstName: firstName || '',
      lastName: lastName || '',
      role: {
        id: dbUser.role,
        name: dbUser.role.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()),
        description: this.getRoleDescription(dbUser.role),
        level: dbUser.role_level,
        permissions: this.getRolePermissions(dbUser.role)
      },
      department: 'Security Operations', // Default department
      isActive: dbUser.is_active,
      lastLogin: dbUser.last_login ? new Date(dbUser.last_login) : undefined,
      createdAt: new Date(dbUser.created_at),
      createdBy: dbUser.createdBy || '',
      permissions: this.getRolePermissions(dbUser.role)
    };
  }

  private getRoleDescription(role: string): string {
    switch (role) {
      case 'security_admin':
        return 'Full system administration access';
      case 'security_manager':
        return 'Manage security operations and team';
      case 'security_analyst':
        return 'Analyze threats and manage incidents';
      case 'security_viewer':
        return 'Read-only access to security data';
      default:
        return 'Standard user access';
    }
  }

  private getRolePermissions(role: string) {
    const basePermissions = [
      { id: '1', name: 'view_dashboard', description: 'View dashboard', resource: 'dashboard', action: 'read' },
      { id: '2', name: 'view_incidents', description: 'View incidents', resource: 'incidents', action: 'read' }
    ];

    switch (role) {
      case 'security_admin':
        return [
          ...basePermissions,
          { id: '3', name: 'manage_users', description: 'Manage users', resource: 'users', action: 'write' },
          { id: '4', name: 'manage_system', description: 'System administration', resource: 'system', action: 'write' },
          { id: '5', name: 'manage_incidents', description: 'Manage incidents', resource: 'incidents', action: 'write' }
        ];
      case 'security_manager':
        return [
          ...basePermissions,
          { id: '5', name: 'manage_incidents', description: 'Manage incidents', resource: 'incidents', action: 'write' },
          { id: '6', name: 'view_reports', description: 'View reports', resource: 'reports', action: 'read' }
        ];
      case 'security_analyst':
        return [
          ...basePermissions,
          { id: '7', name: 'analyze_threats', description: 'Analyze threats', resource: 'threats', action: 'write' }
        ];
      default:
        return basePermissions;
    }
  }
  async logout(): Promise<void> {
    this.currentUser = null;
    localStorage.removeItem('currentUser');
  }

  getCurrentUser(): User | null {
    if (this.currentUser) return this.currentUser;

    const stored = localStorage.getItem('currentUser');
    if (stored) {
      try {
        this.currentUser = JSON.parse(stored);
        return this.currentUser;
      } catch {
        localStorage.removeItem('currentUser');
      }
    }
    return null;
  }

  async createUser(userData: CreateUserData, createdBy: string): Promise<User> {
    // Check for existing username or email
    const { data: existing, error: fetchError } = await supabase
      .from('users')
      .select('id')
      .or(`username.eq.${userData.username},email.eq.${userData.email}`);

    if (fetchError) throw fetchError;
    if (existing && existing.length > 0) {
      throw new Error('Username or email already exists');
    }

    // Hash password (in production, use proper password hashing)
    // For demo purposes, we'll store a simple hash
    const passwordHash = await this.hashPassword(userData.password);

    // Get role information
    const roleInfo = this.getRoleInfo(userData.roleId);

    // Insert new user into database
    const { data, error } = await supabase
      .from('users')
      .insert([
        {
          username: userData.username,
          password_hash: passwordHash,
          email: userData.email,
          full_name: `${userData.firstName} ${userData.lastName}`,
          role: userData.roleId,
          role_level: roleInfo.level,
          createdBy,
          is_active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) throw error;
    
    // Transform and return the created user
    return this.transformDbUserToAppUser(data);
  }

  private async hashPassword(password: string): Promise<string> {
    // In production, use bcrypt or similar
    // For demo purposes, we'll use a simple hash
    return btoa(password); // Base64 encoding (NOT secure for production)
  }

  private getRoleInfo(roleId: string) {
    const roles = {
      'security_admin': { level: 1, name: 'Security Administrator' },
      'security_manager': { level: 2, name: 'Security Manager' },
      'security_analyst': { level: 3, name: 'Security Analyst' },
      'security_viewer': { level: 4, name: 'Security Viewer' }
    };
    return roles[roleId] || { level: 4, name: 'Security Viewer' };
  }

  async updateUser(userId: string, updates: Partial<User>): Promise<User> {
    // Transform app user format to database format
    const dbUpdates: any = {
      updated_at: new Date().toISOString()
    };

    if (updates.role) {
      dbUpdates.role = updates.role.id || updates.role.name.toLowerCase().replace(' ', '_');
      dbUpdates.role_level = updates.role.level;
    }

    if (updates.firstName || updates.lastName) {
      const currentUser = await this.getUserById(userId);
      const firstName = updates.firstName || currentUser?.firstName || '';
      const lastName = updates.lastName || currentUser?.lastName || '';
      dbUpdates.full_name = `${firstName} ${lastName}`;
    }

    if (updates.email) dbUpdates.email = updates.email;
    if (updates.isActive !== undefined) dbUpdates.is_active = updates.isActive;

    const { data, error } = await supabase
      .from('users')
      .update(dbUpdates)
      .eq('id', userId)
      .select()
      .single();

    if (error) throw error;
    return this.transformDbUserToAppUser(data);
  }

  private async getUserById(userId: string): Promise<User | null> {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (error || !data) return null;
    return this.transformDbUserToAppUser(data);
  }

  async deleteUser(userId: string): Promise<void> {
    // Soft delete - set is_active to false
    const { error } = await supabase
      .from('users')
      .update({ 
        is_active: false,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId);

    if (error) throw error;
  }

  async getAllUsers(): Promise<User[]> {
    const { data, error } = await supabase
      .from('users')
      .select(`
        id,
        username,
        email,
        full_name,
        role,
        role_level,
        is_active,
        last_login,
        created_at,
        updated_at,
        createdby
      `)
      .eq('is_active', true)
      .order('created_at', { ascending: false });

    if (error) throw error;
    return data.map(user => this.transformDbUserToAppUser(user));
  }

  async getAllRoles(): Promise<UserRole[]> {
    // Return predefined roles since they're not stored in a separate table
    return [
      {
        id: 'security_admin',
        name: 'Security Administrator',
        description: 'Full system administration access',
        level: 1,
        permissions: this.getRolePermissions('security_admin')
      },
      {
        id: 'security_manager',
        name: 'Security Manager',
        description: 'Manage security operations and team',
        level: 2,
        permissions: this.getRolePermissions('security_manager')
      },
      {
        id: 'security_analyst',
        name: 'Security Analyst',
        description: 'Analyze threats and manage incidents',
        level: 3,
        permissions: this.getRolePermissions('security_analyst')
      },
      {
        id: 'security_viewer',
        name: 'Security Viewer',
        description: 'Read-only access to security data',
        level: 4,
        permissions: this.getRolePermissions('security_viewer')
      }
    ];
  }

  hasPermission(user: User, resource: string, action: string): boolean {
    return user.permissions?.some(p => p.resource === resource && p.action === action) ?? false;
  }

  canManageUsers(user: User): boolean {
    return this.hasPermission(user, 'users', 'write') || user.role.level <= 2;
  }
}

export const authService = new AuthService();
