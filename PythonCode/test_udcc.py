import sys
import time
from udcc import *

base_dir = 'decompositions/'

ds_range = {'americas_large': (278, 556, 834, 1111, 1389, 1667, 1944, 2222, 2500, 2777, 3055, 3333),
            'americas_small': (281, 562, 843, 1124, 1405, 1686, 1967, 2248, 2529, 2809, 3090, 3371),
            'apj': (28, 56, 84, 112, 139, 167, 195, 223, 251, 278, 306, 334),
            'customer': (419, 837, 1256, 1674, 2092, 2511, 2929, 3348, 3766, 4184, 4603, 5021),
            'domino': (6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 57, 62),
            'emea': (1, 2, 3, 4),
            'fire1': (21, 41, 61, 82, 102, 122, 143, 163, 183, 203, 224, 244),
            'fire2': (24, 48, 72, 96, 120, 144, 168, 192, 216, 239, 263, 287),
            'hc': (3, 6, 9, 11, 14, 17, 19, 22, 25, 27, 30, 33)
            }

datasets = ['americas_large',
            'americas_small',
            'apj',
            'customer',
            'domino',
            'emea',
            'fire1',
            'fire2',
            'hc']

dataset_name = dict(map(lambda d: (d, ' '.join(d.split('_')).title()), datasets))
dataset_name['hc'] = 'Healthcare'
dataset_name['fire1'] = 'Firewall 1'
dataset_name['fire2'] = 'Firewall 2'

decomp_names = ['_optimal_cover.txt',
                '_org_row.txt',
                '_unc_row.txt',
                '_org_col.txt',
                '_unc_col.txt',
                '_fastMin.txt',
                '_fastMin_v2.txt',
                '_obmd.txt',
                '_biclique.txt']

# if heuristics='both', then test_udcc executes the heuristics first on the starting decomposition
# and then on the reduced decomposition
def test_udcc(dataset, decompositions, murs, heuristics='reduced', output='terminal'):
    all_wsc = ''
    all_nr = ''
    all_time = ''
    starting_dataset = 'datasets/' + dataset + '.txt'
    for mur in murs:
        print('mur:', mur)
        l_nr = list()
        l_wsc = list()
        l_time = list()
        start = time.process_time_ns()
        state = UDCC_1(starting_dataset, mur)
        state.mine()
        span = time.process_time_ns() - start
        wsc, nr, _, _ = state.get_wsc()
        l_nr.append(nr)
        l_wsc.append(wsc)
        l_time.append(span // 1000)

        start = time.process_time_ns()
        state = UDCC_2(starting_dataset, mur)
        state.mine()
        span = time.process_time_ns() - start
        wsc, nr, _, _ = state.get_wsc()
        l_nr.append(nr)
        l_wsc.append(wsc)
        l_time.append(span // 1000)

        for decomposition in decompositions:
            starting_state = base_dir + dataset + decomposition
            if heuristics == 'both':
                if dataset == 'customer' and 'optimal' in decomposition:
                    nr, wsc, span = 0, 0, 0
                else:
                    start = time.process_time_ns()
                    state = POST_UDCC(starting_state, mur)
                    state.mine()
                    span = time.process_time_ns() - start
                    wsc, nr, _, _ = state.get_wsc()
                l_nr.append(nr)
                l_wsc.append(wsc)
                l_time.append(span // 1000)

            if dataset == 'customer' and 'optimal' in decomposition:
                nr, wsc, span = 0, 0, 0
            else:
                start = time.process_time_ns()
                state = POST_UDCC(starting_state, mur, True)  # remove redundant/unused roles
                state.mine()
                span = time.process_time_ns() - start
                wsc, nr, _, _ = state.get_wsc()
            l_nr.append(nr)
            l_wsc.append(wsc)
            l_time.append(span // 1000)

        m_nr = min(l_nr)
        s_nr = f'{mur:>4}'
        m_wsc = min(l_wsc)
        s_wsc = f'{mur:>4}'
        m_tm = min(l_time)
        s_tm = f'{mur:>4}'

        for i in range(len(l_wsc)):
            if l_nr[i] <= m_nr:
                s_nr = s_nr + ' & \\bf ' + f'{l_nr[i]:>6}'
            else:
                s_nr = s_nr + ' & ' + f'{l_nr[i]:>10}'

            if l_wsc[i] <= m_wsc:
                s_wsc = s_wsc + ' & \\bf ' + f'{l_wsc[i]:>6}'
            else:
                s_wsc = s_wsc + ' & ' + f'{l_wsc[i]:>10}'

            if l_time[i] <= m_tm:
                s_tm = s_tm + ' & \\bf ' + f'{l_time[i]:>6}'
            else:
                s_tm = s_tm + ' & ' + f'{l_time[i]:>10}'

        all_nr = all_nr + s_nr + '\\\ \n'
        all_wsc = all_wsc + s_wsc + '\\\ \n'
        all_time = all_time + s_tm + '\\\ \n'

    header = '\\begin{table}[h]\n' + \
             '\centering\n' + \
             '\small{\n' + \
             '\\begin{tabular}{c' + 'r' * (len(decompositions) + 1) * 2 + '} \hline \n'

    header += ' mru & '
    fields = ['A1', 'A2']
    for i in range(1, len(decompositions) + 1):
        if heuristics == 'both':
            fields.append('d' + str(i))
        fields.append('r' + str(i))

    for h in fields:
        header = header + f'{h:^10}' + ' & '

    if output == 'file':
        stdout = sys.stdout
        sys.stdout = open('UDCC_experiments/' + dataset + '.tex', 'w')

    print(f'\\section{{Dataset {dataset_name[dataset]}}}')
    print()
    print(header[:-3] + '\\\ ')
    print(all_nr)
    footer_r = '\end{tabular}\n' + \
               f'\caption{{Role-set size for dataset {dataset_name[dataset]} }}\n' + \
               f'\label{{tab_{dataset}_r}}' + \
               '\n}\n\end{table}'
    print(footer_r)
    print('\n')

    print(header[:-3] + '\\\ ')
    print(all_wsc)
    footer_w = '\end{tabular}\n' + \
               f'\caption{{$WSC$ values for dataset {dataset_name[dataset]} }}\n' + \
               f'\label{{tab_{dataset}_w}}' + \
               '\n}\n\end{table}'
    print(footer_w)
    print('\\clearpage')

    print(header[:-3] + '\\\ ')
    print(all_time)
    footer_t = '\end{tabular}\n' + \
               f'\caption{{Execution times for dataset {dataset_name[dataset]} }}\n' + \
               f'\label{{tab_{dataset}_t}}' + \
               '\n}\n\end{table}'
    print(footer_t)
    print('\\clearpage')
    print('\n')

    if output == 'file':
        sys.stdout.close()
        sys.stdout = stdout



if __name__ == '__main__':
    pass
    for ds_name, tics in ds_range.items():
        print(ds_name, tics)
        if 'hc' in ds_name:
            test_udcc(ds_name, decomp_names, tics, output='terminal')