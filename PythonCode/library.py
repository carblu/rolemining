from copy import deepcopy

class POST:
    def __init__(self, state):
        self._upa = {}  # dictionary (user, set of permissions)
        self._permissions = set()
        self._orig_ua = dict()    # original ua
        self._orig_pa = dict()    # original pa
        self._ua = dict()         # post-processed ua
        self._pa = dict()         # post-processed pa
        self._nr = 0              # number of roles
        self._state = state       # starting RBAC state (file containing a representation of UA and PA)
        self._load_ua_pa()
        self._users = set(self._orig_ua.keys())
        self._original_users = deepcopy(self._users)

    def _load_ua_pa(self):
        f = open(self._state, 'r')
        for line in f:
            if 'role' in line:
                r = int(line.split(':')[1])
                # print('role: ', r)
            elif 'permissions' in line:
                permissions = line.split(':')[1]
                permissions = set(map(int, permissions.split(',')))
                self._orig_pa[r] = permissions
                # print('permissions: ', pa[r])
            elif 'users' in line:
                users = line.split(':')[1]
                users = set(map(int, users.split(',')))
                # print('users: ', users)

                for u in users:
                    if u in self._orig_ua.keys():
                        self._orig_ua[u].add(r)
                    else:
                        self._orig_ua[u] = {r}

                    if u in self._upa:
                        self._upa[u].update(permissions)
                    else:
                        self._upa[u] = deepcopy(permissions)
        f.close()

    def _update_ua_pa(self, usrs, role):

        if role not in self._pa.values():
            self._nr += 1
            self._pa[self._nr] = role
            found = self._nr
        else:
            found = [r for (r, prms) in self._pa.items() if prms == role][0]

        for u in usrs:
            if u in self._ua:
                self._ua[u].add(found)
            else:
                self._ua[u] = {found}

    def _cs(self):
        if len(self._ua) != len(self._original_users):
            #print('Failed #users', '*mined users', len(self._ua), '#orig users', len(self._original_users))
            return False

        flag = True
        for u in self._ua:
            perms = set()
            for r in self._ua[u]:
                perms.update(self._pa[r])
            if perms != self._upa[u]:
                # print('user', u)
                # print('original', self._upa[u])
                # print('assigned', perms)
                # print()
                flag = False, u
                break
                #return False
        return flag


    def check_solution(self):
        if set(self._ua.keys()) != set(self._orig_ua.keys()):
            return False

        for u in self._ua.keys():
            s1 = set()
            s2 = set()
            for r in self._orig_ua[u]:
                s1.update(self._orig_pa[r])
            for r in self._ua[u]:
                s2.update(self._pa[r])

            if s1 != s2:
                return False

        return True

    def _check_soundness_starting_state(self):
        if set(self._orig_ua.keys()) != set(self._upa.keys()):
            return False

        for u in self._orig_ua.keys():
            s = set()
            for r in self._orig_ua[u]:
                s.update(self._orig_pa[r])

            if s != self._upa[u]:
                return False

        return True

    def get_wsc(self):
        nroles = len(self._pa.keys())
        ua_size = 0
        for roles in self._ua.values():
            ua_size += len(roles)
        pa_size = 0
        for prms in self._pa.values():
            pa_size += len(prms)
        return nroles + ua_size + pa_size, nroles, ua_size, pa_size

class Mining:
    def __init__(self, dataset, unique = False):
        if type(dataset) != str and type(dataset) != dict:
            raise Exception('Dataset error: wrong format')

        self._users = set()
        self._permissions = set()
        self._upa = {}  # dictionary (user, set of permissions)
        self._upa_unique = {}  # dictionary (user, set of permissions) only users with distinct set of permissions
        self._pua = {}  # dictionary (permission, set of users)
        self._ua = {}   # dictionary (user, set of roles)
        self._pa = {}   # dictionary (role, set of permissions)
        self._k = 0     # mined roles so far
        self._n = 0     # total number of granted access to resources (i.e., number of pairs in dataset)

        if type(dataset) == str:
            self._dataset = dataset
            self._load_upa()
        else: # the dataset is represented by a dictionary (UPA)
            self._dataset = '-- direct upa inizialization --'
            self._upa = dataset
            self._users = set(self._upa.keys())
            for u, prms in self._upa.items():
                self._permissions = self._permissions.union(prms)
                self._n += len(prms)
                for p in prms:
                    if p in self._pua:
                        self._pua[p].add(u)
                    else:
                        self._pua[p] = {u}

        if unique:  # collapse users having the same set of permissions to just one user
            self._unique_users()

        self._unc_upa = deepcopy(self._upa)
        self._unc_pua = deepcopy(self._pua)
        self._unc_users = deepcopy(self._users)
        self._unc_permissions = deepcopy(self._permissions)

    def _load_upa(self):
        with open(self._dataset) as f:
            for u_p in f:
                (user, permission) = u_p.split()
                user = int(user.strip())
                permission = int(permission.strip())

                if user in self._users:
                    if permission not in self._upa[user]:
                        self._upa[user].add(permission)
                        self._n = self._n + 1
                else:
                    self._users.add(user)
                    self._upa[user] = {permission}
                    self._n = self._n + 1

                if permission in self._permissions:
                    self._pua[permission].add(user)
                else:
                    self._permissions.add(permission)
                    self._pua[permission] = {user}
            f.close()

    def roles(self):
        return self._pa

    def _unique_users(self):
        self._users_bk = deepcopy(self._users)  # users backup
        self._upa_bk = deepcopy(self._upa)      # upa backup
        self._users_map = dict()                #key = user, value=list of users with identical permissions
        equal_prms = dict()
        for u in self._users:
            equal_prms[u] = u
        self._upa = dict()

        for u_i in sorted(self._upa_bk.keys()):
            for u_j in sorted(self._upa_bk.keys()):
                if u_j > u_i and equal_prms[u_j] == u_j and self._upa_bk[u_j] == self._upa_bk[u_i]:
                    equal_prms[u_j] = u_i #u_j's permissions are identical to u_i's ones


        for k, v in equal_prms.items():
            if v not in self._users_map:
                self._users_map[v] = [k]
            else:
             self._users_map[v].append(k)

        # reduced user-permission association
        for u in self._users_map:
            self._upa[u] = deepcopy(self._upa_bk[u])

        self._users = set(self._users_map.keys())

    def _update_ua_pa(self, usrs, prms):
        idx_f = 0
        for (idx, r) in self._pa.items():
            if r == prms:
                idx_f = idx
                break
        else:
            self._k += 1
            self._pa[self._k] = prms
            idx_f = self._k

        for u in usrs:
            if u in self._ua:
                self._ua[u].add(idx_f)
            else:
                self._ua[u] = {idx_f}

    def _update_unc(self, usrs, prms):
        for u in usrs:
            self._unc_upa[u] = self._unc_upa[u] - prms
            if len(self._unc_upa[u]) == 0:
                self._unc_users.remove(u)
        for p in prms:
            self._unc_pua[p] = self._unc_pua[p] - usrs
            if len(self._unc_pua[p]) == 0 and p in self._unc_permissions:
                self._unc_permissions.remove(p)

    def get_wsc(self):
        nroles = len(self._pa.keys())
        ua_size = 0
        for roles in self._ua.values():
            ua_size += len(roles)
        pa_size = 0
        for prms in self._pa.values():
            pa_size += len(prms)
        return nroles + ua_size + pa_size, nroles, ua_size, pa_size

    def _check_solution(self):
        for u in self._users:
            if u not in self._ua.keys():
                return 1, False
            perms = set()
            for r in self._ua[u]:
                perms.update(self._pa[r])
            if perms != self._upa[u]:
                return 2, False
        return True

    def _check_unused_roles(self):
        roles = set()
        for r in self._ua.values():
            roles.update(r)
        if roles != set(self._pa.keys()):
            return True
        else:
            return False

    def print_roles(self):
        sr = sorted(self._pa.items(), key = lambda role : len(role[1]))
        for r in sr:
            print(r)

    def __str__(self):
        to_return = '-- dati dataset/esperimento --\n'
        to_return = to_return + self._dataset + '\n'
        to_return = to_return + '#utenti:' + str(len(self._users)) + '\n'
        to_return = to_return + '#permessi:' + str(len(self._permissions)) + '\n'
        to_return = to_return + '|upa|=' + str(self._n) + '\n'
        return to_return


    def check_duplicates(self):
        print('-- check duplicates --')
        tmp_roles = list(self._pa.values())
        print('    #initial roles', len(tmp_roles))
        roles = []
        for r in tmp_roles:
            if r not in roles:
                roles.append(r)
        print('    #final roles', len(roles))
        if len(tmp_roles) == len(roles):
            print('    No duplicated roles')
        else:
            print('    DUPLICATED roles')

    def duplicated_users(self):
        tmp_users = []
        for u in self._upa.values():
            if u not in tmp_users:
                tmp_users.insert(1, u)
            else:
                print(u, 'già presente')
        print(len(self._users), ' ', len(tmp_users))
        if len(tmp_users) != len(self._users):
            return True
        else:
            return False

    def get_dupa(self):
        _dupa = 0
        for u in self._users:
            if u not in self._ua.keys():
                _dupa = _dupa + len(self._upa[u])
            else:
                prms = set()
                for r in self._ua[u]:
                    prms = prms.union(self._pa[r])
                if prms.issubset(self._upa[u]):
                    _dupa = _dupa + len(self._upa[u] - prms)
                else:
                    print('ERROR!!!')
                    exit(0)
        return _dupa

    def verify(self):
        num_perms = 0
        for u in self._ua.keys():
            prms = set()
            for r in self._ua[u]:
                prms = prms.union(self._pa[r])
            num_perms = num_perms + len(prms)
        dupa = self._n - num_perms
        return dupa
