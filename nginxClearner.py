__author__ = '52691'
import re
from collections import defaultdict
#tool https://regex101.com/
class NginxClearner:
    def __init__(self,path):
        self.path=path
        self.record=[]
        with open (path,'r') as file:
            line=file.readline().strip()
            while line:
                self.record.append(self._getRecord(line))
                line=file.readline()

    def _getRecord(self,lineIn):
        try:
            line=re.match('([\d\.]+) - ([^ ]*) \[([^\]]*)\] \"([^\"]*)\" (\d+) (\d+) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\"',lineIn)
            remote_addr = line.group(1)#
            remote_user = line.group(2)
            time_local = line.group(3)#
            request = line.group(4)#
            if len(request.split(" "))==3:
                 request = line.group(4).split(" ")[1]
            status = line.group(5)#
            bytes_sent = line.group(6)
            http_referer = line.group(7) #https://en.wikipedia.org/wiki/HTTP_referer
            http_user_agent = line.group(8)#
            gzip_ratio = line.group(9)
            return (remote_addr,time_local,request,status,http_user_agent)
        except:
            print("error happens at line:")
            print(lineIn)
            exit(1)

class NginxAnalysis:
    def __init__(self,records):
        self.records=records
        self.abnormal_resp=None
        self.remote_address_visit_times_sorted=None
        self.device_visit_times_sorted=None
        self.requests_sorted=None
        self.__getAbnormalResp()
        self.__get_remote_address_visit_times_sorted()
        self.__get_device_visit_times_sorted()
        self.__get_requests_sorted()

    def __getAbnormalResp(self):
        abnorm_rec=[]
        for record in self.records:
            if record[3]!="200":
                abnorm_rec.append(record)
        self.abnormal_resp=abnorm_rec

    def __get_remote_address_visit_times_sorted(self):
        addrDict=defaultdict(int)
        for record in self.records:
            addrDict[record[0]]+=1
        self.remote_address_visit_times_sorted = sorted(addrDict.items(),key=lambda x:x[1],reverse=True)

    def __get_device_visit_times_sorted(self):
        deviceDict={"Android":0,"ios":0,"PC":0}
        #https://segmentfault.com/a/1190000003735555
        for record in self.records:
            if record[4].find("Android")!=-1:
                deviceDict["Android"]+=1
            elif record[4].find("iPhone")!=-1:
                deviceDict["ios"]+=1
            else:
                deviceDict['PC']+=1
        self.device_visit_times_sorted=deviceDict

    def __get_requests_sorted(self):
        reqDict=defaultdict(int)
        for record in self.records:
            reqDict[record[2]]+=1
        self.requests_sorted=sorted(reqDict.items(),key=lambda x:x[1],reverse=True)

cleanedRecords=NginxClearner("access.log").record
info=NginxAnalysis(cleanedRecords)
print(info.abnormal_resp)
print(info.device_visit_times_sorted)
print(info.remote_address_visit_times_sorted[:5])
print(info.requests_sorted)
