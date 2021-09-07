import abc
import random
from copy import deepcopy
from library import POST
from library import Mining


class POST_UDCC(POST):
    def __init__(self, state, mur, reduce=False):
        super().__init__(state)
        self._ur = dict()  # key: role - values: users assigned to key
        self._mur = mur  # maximum users per role
        self._reduce = reduce
        self._ua = deepcopy(self._orig_ua)
        self._pa = deepcopy(self._orig_pa)

    def _update_ur(self):
        for user, roles in self._ua.items():
            for r in roles:
                if r not in self._ur:
                    self._ur[r] = [user]
                else:
                    self._ur[r].append(user)

    def redundant_roles(self):
        self._redundant = dict()
        for user, roles in self._ua.items():
            to_check = sorted([(r, self._pa[r]) for r in roles], key=lambda t: len(t[1]))
            # print(user, to_check)
            for i in range(len(to_check) - 1):
                for j in range(i + 1, len(to_check)):
                    if to_check[i][1] <= to_check[j][1]:
                        if user in self._redundant:
                            self._redundant[user].add(to_check[i][0])
                        else:
                            self._redundant[user] = {to_check[i][0]}

        return self._redundant

    def remove_redundant_roles(self):
        for user, roles in self._redundant.items():
            if not (roles <= self._ua[user]):
                print('ERROR!!!!')
            self._ua[user] = self._ua[user] - roles

    def unused_roles(self):
        all_roles = set()
        for roles in self._ua.values():
            all_roles.update(roles)

        return set(self._pa.keys()) - all_roles if set(self._pa.keys()) != all_roles else {}

    def remove_unused_roles(self, to_remove):
        for role in to_remove:
            del self._pa[role]

    def mine(self):
        if self._reduce:  # first remove reduntant roles then remove, if any, unused roles
            if self.redundant_roles():
                self.remove_redundant_roles()
                if u_r := self.unused_roles():
                    self.remove_unused_roles(u_r)

        self._update_ur()
        nr = max(self._pa.keys())
        for role, users in self._ur.items():
            if len(users) > self._mur:
                i_u = 0  # number of users for which we modified the role assignments
                for u in users[self._mur:]:
                    self._ua[u].remove(role)
                    if i_u % self._mur == 0:
                        nr += 1
                        self._pa[nr] = deepcopy(self._pa[role])
                    i_u += 1
                    self._ua[u].add(nr)


class STRICT_UDCC(Mining):
    def __init__(self, dataset, mur, access_matrix='upa', criterion='min', num_iter=10):
        super().__init__(dataset)
        self._mur = len(self._users) if mur == 0 else mur  # maximum users per role
        self._num_iter = num_iter  # number of times the heuristic tries to generate pair of roles (see _split)
        self._au = dict()  # key: role - value: number of users assogned to key
        self._forbidden_roles = list()  # role assigned to mur users
        self._dupa = dict()  # direct user-to-permission assignment

        # use the original UPA or the entries left uncovered in UPA
        self._matrix = self._upa if access_matrix == 'upa' else self._unc_upa

        # select the minimum weight row (criterion ='min') or the maximum weight row
        self._selection = min if criterion == 'min' else max

    def _pick_role(self):
        # select a pair (user, role) according the fixed criterion in the specified access_matrix
        u, prms = self._selection([(u, self._matrix[u]) for u in self._unc_users],
                                  key=lambda t: len(t[1]))
        prms = self._unc_upa[u]
        if prms not in self._forbidden_roles:
            to_return = [u, prms]  # return user and role
        else:  # split the role as it already reached the UDCC constraint (i.e., mur)
            # print('FORBIDEN ROLE', prms)
            # Cannot split a role with a single permission it will be handled by DUPA
            if len(prms) == 1:
                roles = [None, None]
            else:
                roles = self._split(prms)
            # print('returned by _split:       ', roles)
            to_return = [u, roles[0], roles[1]]

        return to_return

    def _split(self, prms):
        # any considered role is a proper subset of prms
        all_contained_roles = [(role, self._au[r]) for r, role in self._pa.items()
                               if role < prms and self._au[r] < self._mur]

        # first check pairs of existing roles satisfying the UDCC constraint
        to_check = list()
        for i in range(len(all_contained_roles) - 1):
            for j in range(i + 1, len(all_contained_roles)):
                if all_contained_roles[i][0].union(all_contained_roles[j][0]) == prms:
                    to_check.append((all_contained_roles[i][0], all_contained_roles[j][0],
                                     all_contained_roles[i][1] + all_contained_roles[j][1]))

        # If no pair of existing roles covers prms, consider any contained role
        # in prms and its complement with respect to prms. Consider the complement
        # only if it is not a mined role (i.e., it does not appear in PA)
        if not to_check:
            for (role, nau) in all_contained_roles:
                if prms - role not in self._pa.values():
                    to_check.append((role, prms - role, nau))

        if to_check:
            # If some roles pair has been found, take the one with least sum mur values (i.e., min nau)
            to_return = min(to_check, key=lambda t: t[2])[:2]  # take the first two elements (i.e., the roles)
        else:
            # try num_iter times to generate two random new roles covering prms
            i = 0
            while i < self._num_iter:
                i += 1
                np = random.randint(1, len(prms) - 1)  # len(prms) -1 to avoid the generation of prms
                r1 = set(random.sample(list(prms), np))
                r2 = prms - r1

                if r1 in self._pa.values() or r2 in self._pa.values():
                    continue  # if either r1 or2 already has been mined, try again
                else:
                    to_return = [r1, r2]
                    break
            else:  # If roles generation fails num_iter times, give up and handle prms by DUPA
                to_return = [None, None]  # no roles found

        # print('SPLIT:', to_return)
        return to_return

    def _update_ua_pa(self, u_to_add, prms):  # _u_ is not used
        usrs = set()
        # Look for role's index, if any
        idx = 0
        if in_pa := [r for (r, role) in self._pa.items() if role == prms]:
            idx = in_pa[0]

        '''
        if idx:
            if self._au[idx] >= self._mur:
                print('SOMETHING WENT WRONG IN PICKING ROLE', idx)
                print('roles:')
                for id_r, prms_r in self._pa.items():
                    print(id_r, prms_r)
                print('au\n', self._au)
        '''

        # If the role induced by prms is new, than add it to PA
        if not idx:  # prms represents a new role
            self._k += 1
            idx = self._k
            self._pa[idx] = deepcopy(prms)
            self._au[idx] = 0

        # users possessing all permissions in prms some of that have not been covered yet
        user_to_consider = [usr for usr in self._unc_users if prms.issubset(self._upa[usr]) and
                            prms.intersection(self._unc_upa[usr])]

        # Done to add user u_to_add to the set of users the role induced by prms
        user_to_consider.remove(u_to_add)
        user_to_consider.insert(0, u_to_add)

        for u in user_to_consider:
            if self._au[idx] < self._mur:
                usrs.add(u)
                self._au[idx] += 1
                if u in self._ua:
                    self._ua[u].add(idx)
                else:
                    self._ua[u] = {idx}

                # If the role (prms) at index idx has already reached the maximum number of
                # allowed users (i.e., mur), then mark it as forbidden and  stop searching for
                # other usrers to assign prms to
                if self._au[idx] == self._mur:
                    self._forbidden_roles.append(self._pa[idx])
                    break
            else:
                break

        return usrs  # users that have been assigned role induced by prms

    def mine(self):
        while self._unc_users:
            result = self._pick_role()  # result = [user, r1, r2] (r2 might be not present)
            u = result[0]
            if result[1] is not None:  # assign roles to u and to at most mur other users containing them
                for role in result[1:]:
                    users = self._update_ua_pa(u, role)
                    # print('affected users:', users)
                    self._update_unc(users, role)
            else:  # assign uncovered permissions through DUPA
                # print('FILLING DUPA')
                self._dupa[u] = deepcopy(self._unc_upa[u])
                self._update_unc({u}, self._unc_upa[u])

    def check_solution(self):
        covered = True
        if self._users != set(self._upa.keys()):
            print('ERROR: skipped user in UA')
            print(set(self._upa.keys()).symmetric_difference(self._users))
            covered = False

        for u in self._users:
            if u not in self._ua:
                if u not in self._dupa:
                    print('ERROR: skipped user', u)
                    covered = False
                    # break
                if self._dupa[u] != self._upa[u]:
                    print('ERROR: wrong DUPA assignment')
                    covered = False
                    # break
            else:
                perms = set()
                for r in self._ua[u]:
                    perms.update(self._pa[r])
                if u in state._dupa:
                    perms.update(self._dupa[u])

                if perms != self._upa[u]:
                    print('uncovered permissions for user', u, 'uncovered permissions', self._upa[u] - perms)
                    covered = False
                    # break

        return covered

    def get_dupa(self):
        dupa = 0
        for u, permissions in self._dupa.items():
            dupa += len(permissions)
        return dupa

    def verify_dupa_covering(self):
        for u in self._dupa:
            prms = deepcopy(self._dupa[u])
            for i, r in self._pa.items():
                if r <= self._dupa[u] and self._au[i] < self._mur:
                    prms = prms - r

            if not prms:
                print('ATTENTION!!!')
                print('  permissions assigned to user ', u, ' by DUPA can be covered by mined roles')


class STRICT_UDCC_REDUCE(STRICT_UDCC, POST_UDCC):
    def mine(self):
        super().mine()
        wsc, nr, ua, pa = self.get_wsc()
        dupa = self.get_dupa()
        print(f'{nr:>5} & {wsc:>7} & {ua:>7} & {pa:>7} & {dupa:>5}')

        if self.redundant_roles():
            print('redundant roles')
            self.remove_redundant_roles()
            if u_r := self.unused_roles():
                self.remove_unused_roles(u_r)

        wsc, nr, ua, pa = self.get_wsc()
        dupa = self.get_dupa()
        print(f'{nr:>5} & {wsc:>7} & {ua:>7} & {pa:>7} & {dupa:>5}')



# abstract class
class UDCC(Mining, abc.ABC):
    def __init__(self, dataset, mur=0):
        super().__init__(dataset)
        self._mur = len(self._users) if mur == 0 else mur  # maximum users per role

    @abc.abstractmethod
    def _pick_role(self):
        pass

    def _update_ua_pa(self, usrs, prms):
        self._k += 1
        self._pa[self._k] = prms
        for u in usrs:
            if u in self._ua:
                self._ua[u].add(self._k)
            else:
                self._ua[u] = {self._k}

    def _update_unc(self, usrs, prms):
        for u in usrs:
            self._unc_upa[u] = self._unc_upa[u] - prms
            if len(self._unc_upa[u]) == 0:
                del self._unc_upa[u]
                self._unc_users.remove(u)
        for p in prms:
            if p in self._unc_pua:
                self._unc_pua[p] = self._unc_pua[p] - usrs
                if len(self._unc_pua[p]) == 0 and p in self._unc_permissions:
                    del self._unc_pua[p]
                    self._unc_permissions.remove(p)

    def mine(self):
        while len(self._unc_users) > 0:
            usrs, prms = self._pick_role()
            if usrs:
                self._update_ua_pa(usrs, prms)
                self._update_unc(usrs, prms)


class UDCC_1(UDCC):
    def _pick_role(self):
        u, prms = min(self._unc_upa.items(), key=lambda t: len(t[1]))

        all_usrs = [(u, self._unc_upa[u]) for u in self._unc_users if prms <= self._unc_upa[u]]
        # try also _unc_upa
        # all_usrs = [(u, self._unc_upa[u]) for u in self._unc_users if prms <= self._upa[u]]

        all_usrs.sort(key=lambda t: len(t[1]), reverse=True)
        usrs = [t[0] for t in all_usrs]

        if len(usrs) > self._mur:
            return set(usrs[:self._mur]), prms
        else:
            return set(usrs), prms


class UDCC_2(UDCC):
    def _pick_role(self):
        u, u_min = min(self._unc_upa.items(), key=lambda t: len(t[1]))
        p, p_min = min(self._unc_pua.items(), key=lambda t: len(t[1]))

        usrs, prms = self._pick_role_u(u) if u_min <= p_min else self._pick_role_p(p)

        return usrs, prms

    def _pick_role_u(self, u):  # the selected node is a user
        prms = self._unc_upa[u]
        usrs = [u for u in self._unc_users if prms <= self._unc_upa[u]]
        if len(usrs) > self._mur:
            return set(usrs[:self._mur]), prms
        else:
            return set(usrs), prms

    def _pick_role_p(self, p):  # the selected node is a permission
        all_usrs = list(self._unc_pua[p])
        if len(all_usrs) > self._mur:
            usrs = set(all_usrs[:self._mur])
        else:
            usrs = set(all_usrs)

        prms = {p for p in self._unc_permissions if usrs <= self._pua[p]}

        return usrs, prms


class UDCC_RM_1(UDCC):
    def _pick_role(self):
        u, prms = min([(u, self._upa[u]) for u in self._unc_users], key=lambda t: len(t[1]))
        # print(u, prms)
        all_usrs = {usr for usr in self._unc_users if prms <= self._upa[usr]}
        #print(all_usrs)
        if len(all_usrs) <= self._mur:
            usrs = all_usrs
            # print(usrs)
        else:
            all_usrs.remove(u)
            new_set = set(list(all_usrs)[:self._mur - 1])
            new_set.add(u)
            usrs = new_set
            # print(usrs)

        #input('xxx')
        return usrs, prms


class UDCC_RM_2(UDCC):
    def _pick_role(self):
        u, prms = min([(u, self._unc_upa[u]) for u in self._unc_users], key=lambda t: len(t[1]))
        all_usrs = {usr for usr in self._unc_users if prms <= self._upa[usr]}
        # print(u, prms)
        all_usrs = {usr for usr in self._unc_users if prms <= self._upa[usr]}
        # print(all_usrs)
        if len(all_usrs) <= self._mur:
            usrs = all_usrs
            #print(usrs)
        else:
            all_usrs.remove(u)
            new_set = set(list(all_usrs)[:self._mur - 1])
            new_set.add(u)
            usrs = new_set
            # print(usrs)

        # input('xxx')
        return usrs, prms


if __name__ == '__main__':
    pass


    dataset = 'hc'
    mur = 4
    dataset_name = 'datasets/' + dataset + '.txt'
    state = STRICT_UDCC(dataset_name, mur, access_matrix='unc_upa', criterion='min')
    state.mine()
    wsc, nr, ua, pa = state.get_wsc()
    print('wsc', wsc, '#roles:', nr, '|ua|:', ua, '|pa|:', pa, '|dupa|:', state.get_dupa())
    print('dupa:', state._dupa)
    print('covered:', state.check_solution())


    dataset = 'americas_large'
    mur = 50
    dataset_name = 'datasets/' + dataset + '.txt'
    state = STRICT_UDCC_REDUCE(dataset_name, mur, access_matrix='unc_upa', criterion='min')
    state.mine()
    print('covered:', state.check_solution())

