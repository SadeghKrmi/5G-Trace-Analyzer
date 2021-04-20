# to define filter in json and output a nested dictionary in python

from copy import copy

def pcapjsonfilter(data, keys):
    result = []
    path = []

    def find_path(data_find_path, key_find_path):
        for k,v in data_find_path.items():
            path.append(k)
            if isinstance(v,dict):
                find_path(v, key_find_path)
            if k == key_find_path:
                element = []
                element.extend(copy(path))
                element.extend([v])
                result.append(element)
            if path != []:
                path.pop()


    def merge(d1, d2):
        for k in d2:
            if k in d1 and isinstance(d1[k], dict) and isinstance(d2[k], dict):
                merge(d1[k], d2[k])
            else:
                d1[k] = d2[k]

    for key in keys:
        find_path(data, key)

    
    final_result = {}
    # print(result)
    for element in result:
        temp_dict = {}
        temp_dict = element[-1]
        for i in range(len(element)-2,-1, -1):
            key = element[i]
            temp_dict = {key: temp_dict}
        merge(final_result, temp_dict)

    return final_result





def pcapjsonfilterSingleParent(data, keys):
    '''
        return a json/list_in_list fields maching keys from pcap ._all_fields
    '''
    def findSingleParam(dictionary, keySingle):
        for key, value in dictionary.items():
            if type(value) is dict:
                yield from findSingleParam(value, keySingle)
            if key == keySingle:
                yield (key, value)


    result = []

    for key in keys:
        result = []
        for x,y in findSingleParam(data, key):
            result.append([x, y])
    # print(result)
    

    return result

