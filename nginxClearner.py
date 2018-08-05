__author__ = '52691'
import re
from collections import defaultdict
import traceback


"""
    项目中使用 https://regex101.com/ 查看正则匹配正确性
    基类作为接口，其他类继承基类基本操作，重载正则清洗等函数，便于拓展
    每个函数要有注释，命名按照PEP8标准，一个函数只做一件事，尽量少于30行
    类的初始化构造函数中不要有逻辑相关的东西，比如操作文件，处理变量等，仅做简单赋值。如果这里出错，debug都找不到原因
    代码格式要标准，pycharm右边干净
"""


class BaseCleaner(object):
    """清洗基类"""

    def __init__(self, file_path):
        self.path = file_path
        # 对于不同的类型日志，可能就是正则和数据名称不一样
        self.re_rule = ""
        self.data_list = []

    def clean(self):
        """读取文件，清洗操作,获取需求数据"""
        data = []
        with open(self.path, 'r') as file:
            line = file.readline().strip()
            while line:
                data.append(self.get_result(line))
                line = file.readline()
        return data

    def get_result(self, raw_line):
        """正则匹配，清洗操作"""
        record = dict()
        line = re.match(self.re_rule, raw_line)
        try:
            # 数据名：数据值 的字典
            for i in range(len(self.data_list)):
                record[self.data_list[i]] = line.group(i+1)
            return record
        except:
            # 异常了需要打印详细堆栈信息，不然很难准确定位问题
            print("error happens at line: %s" % traceback.format_exc())
            print(raw_line)


class NginxCleaner(BaseCleaner):
    def __init__(self, file_path):
        BaseCleaner.__init__(self, file_path)
        self.re_rule = \
            '([\d\.]+) - ([^ ]*) \[([^\]]*)\] \"([^\"]*)\" (\d+) (\d+) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\"'
        self.data_list = ["remote_addr", "remote_user", "time_local", "request",
                          "status", "bytes_sent", "http_referer", "http_user_agent", "gzip_ratio"]

    def get_result(self, raw_line):
        """nginx单独的处理方式"""
        result_dict = super().get_result(raw_line)
        if len(result_dict["request"].split(" ")) == 3:
            result_dict["request"] = result_dict["request"].split(" ")[1]
        return result_dict


class ApacheCleaner(BaseCleaner):
    """假如要清洗apache"""

    def clean(self):
        pass

    def get_result(self, raw_line):
        pass


class BaseAnalysis:
    def __init__(self, records):
        """初始化函数，尽量只要赋值就可以"""
        self.records = records

    def get_abnormal_resp(self):
        abnorm_rec = []
        for record in self.records:
            if record["status"] != "200":
                abnorm_rec.append(record)
        return abnorm_rec

    def get_sorted(self, data_type):
        data_dict = defaultdict(int)
        for record in self.records:
            data_dict[record[data_type]] += 1
        return sorted(data_dict.items(), key=lambda x: x[1], reverse=True)

    def get_device_visit_times_sorted(self):
        """获取访问设备排序"""
        device_dict = {"Android": 0, "ios": 0, "PC": 0}
        # https://segmentfault.com/a/1190000003735555
        for record in self.records:
            if record["http_user_agent"].find("Android") != -1:
                device_dict["Android"] += 1
            elif record["http_user_agent"].find("iPhone") != -1:
                device_dict["ios"] += 1
            else:
                device_dict['PC'] += 1
        return device_dict


class NginxAnalysis(BaseAnalysis):

    def get_remote_address_visit_times_sorted(self):
        return super().get_sorted("remote_addr")

    def get_requests_sorted(self):
        return super().get_sorted("request")


cleanedRecords = NginxCleaner("access.log").clean()

info = NginxAnalysis(cleanedRecords)
print(info.get_abnormal_resp())
print(info.get_device_visit_times_sorted())
print(info.get_remote_address_visit_times_sorted()[:5])
print(info.get_requests_sorted())


