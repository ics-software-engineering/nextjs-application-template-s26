import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { compare } from 'bcrypt';
import { prisma } from '@/lib/prisma';

export const { auth, signIn, signOut, handlers } = NextAuth({
    providers: [Credentials({
        credentials: {
            email: {
                label: 'Email',
                type: 'email',
                placeholder: 'john@foo.com',
            },
            password: { label: 'Password', type: 'password' },
        },
        authorize: async (credentials) => {
            if (!credentials?.email || !credentials.password) {
                return null;
            }
            const user = await prisma.user.findFirst({
                where: {
                    email: credentials.email,
                }
            });
            if (!user) {
                return null;
            }

            const isPasswordValid = await compare(credentials.password as string, user.password);
            if (!isPasswordValid) {
                return null;
            }

            console.log('User authenticated', { user }, 'Returning user object with id, email, and randomKey (role)');
            return {
                id: `${user.id}`,
                email: user.email,
                randomKey: user.role,
            };
        },

    }),
    ],
    pages: {
        signIn: '/auth/signin',
        signOut: '/auth/signout',
        //   error: '/auth/error',
        //   verifyRequest: '/auth/verify-request',
        //   newUser: '/auth/new-user'
    },
    callbacks: {
      session: ({ session, token, user }) => {
      // console.log('Session Callback', { session, token })
      session.user = user;
      return session;
    },
    jwt: ({ token, account }) => {
      // console.log('JWT Callback', { token, user })
      if (account) {
        token.randomKey = account.randomKey;
        token.id = account.id;
      }
      return token;
    },
  },
});
