package sqlrisk

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sunkaimr/sql-risk/comm"
	"net/http"
	"strconv"
	"time"
)

const (
	ThanosURL = "http://thanos-realtime.cowelltech.com/"
	// CPU 5min内的使用率
	cpuUsagePromQL = "avg_over_time(qce_cdb_cpuuserate_max{vip='%s'}[5m])"

	/*
		    https://cloud.tencent.com/document/product/248/50350#.E6.8C.87.E6.A0.87.E8.AF.B4.E6.98.8E
			qce_cdb_volumerate_max      磁盘利用率：磁盘使用空间/实例购买空间
			qce_cdb_capacity_max        磁盘占用空间：包括 MySQL 数据目录和  binlog、relaylog、undolog、errorlog、slowlog 日志空间
			qce_cdb_realcapacity_max    磁盘使用空间：仅包括 MySQL 数据目录，不含 binlog、relaylog、undolog、errorlog、slowlog 日志空间
	*/
	// 磁盘的使用率
	diskUsagePromQL = "qce_cdb_volumerate_max{vip='%s'}"
	// 磁盘的总大小
	diskTotalPromQL = "(qce_cdb_realcapacity_max{vip='%s'}*100)/qce_cdb_volumerate_max{vip='%s'}"
	// 磁盘的使用空间(数据)
	diskUsedPromQL = "qce_cdb_realcapacity_max{vip='%s'}"
	// 磁盘的剩余空间
	diskFreePromQL = "(qce_cdb_realcapacity_max{vip='%s'}*100)/qce_cdb_volumerate_max{vip='%s'}-qce_cdb_realcapacity_max{vip='%s'}"
)

var NoDataPointError = errors.New("no data points found")

type Client struct {
	Url string
}

type MatrixResult struct {
	Status    string     `json:"status"`
	Data      MatrixData `json:"data"`
	ErrorType string     `json:"errorType"`
	Error     string     `json:"error"`
}

type MatrixData struct {
	ResultType string `json:"resultType"`
	Result     []struct {
		Metric interface{}   `json:"metric"`
		Values []interface{} `json:"values"`
	} `json:"result"`
}

type VectorResult struct {
	Status    string     `json:"status"`
	Data      VectorData `json:"data"`
	ErrorType string     `json:"errorType"`
	Error     string     `json:"error"`
}

type VectorData struct {
	ResultType string `json:"resultType"`
	Result     []struct {
		Metric interface{}   `json:"metric"`
		Value  []interface{} `json:"value"`
	} `json:"result"`
}

func NewClient(url string) *Client {
	return &Client{
		Url: url,
	}
}

// QueryRange 查询区间向量
func (c *Client) QueryRange(promQL string, start, end time.Time, step string) (*MatrixData, error) {
	query := make(map[string]string, 0)
	query["query"] = promQL
	query["start"] = fmt.Sprintf("%d", start.Unix())
	query["end"] = fmt.Sprintf("%d", end.Unix())
	query["step"] = step
	body, err := comm.HttpDo(http.MethodGet, c.Url+"/api/v1/query_range", nil, query, "")
	if err != nil {
		return nil, err
	}

	result := MatrixResult{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal [%s] to MatrixResult failed, err: %s", string(body), err)
	}

	if result.Status != "success" {
		return nil, fmt.Errorf(result.ErrorType, result.Error)
	}

	//fmt.Printf("%s", string(body))
	//fmt.Printf("%+v\n", result.Data.Result[0].Values)
	return &result.Data, nil
}

// Query 查询
func (c *Client) Query(promQL string, time time.Time) (*VectorData, error) {
	query := make(map[string]string, 0)
	query["query"] = promQL
	query["time"] = fmt.Sprintf("%d", time.Unix())
	body, err := comm.HttpDo(http.MethodGet, c.Url+"/api/v1/query", nil, query, "")
	if err != nil {
		return nil, err
	}

	result := VectorResult{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal [%s] to MatrixResult failed, err: %s", string(body), err)
	}

	if result.Status != "success" {
		return nil, fmt.Errorf(result.ErrorType, result.Error)
	}

	//fmt.Printf("%s", string(body))
	//fmt.Printf("%+v\n", result.Data.Result[0].Values)
	return &result.Data, nil
}

// CpuUsage 查询cpu的使用率
func (c *Client) CpuUsage(vip string, time time.Time) (float64, error) {
	pql := fmt.Sprintf(cpuUsagePromQL, vip)
	vds, err := c.Query(pql, time)
	if err != nil {
		return 0, fmt.Errorf("query(%s) failed %s", pql, err)
	}
	ret, err := parseData(vds)
	if err != nil {
		return 0, fmt.Errorf("parse query(%s) result, %s", pql, err)
	}
	return ret, nil
}

// DiskUsage 查询磁盘的使用率
func (c *Client) DiskUsage(vip string, time time.Time) (float64, error) {
	pql := fmt.Sprintf(diskUsagePromQL, vip)
	vds, err := c.Query(pql, time)
	if err != nil {
		return 0, fmt.Errorf("query(%s) failed %s", pql, err)
	}
	ret, err := parseData(vds)
	if err != nil {
		return 0, fmt.Errorf("parse query(%s) result, %s", pql, err)
	}
	return ret, nil
}

// DiskTotal 磁盘的总大小（MB）
func (c *Client) DiskTotal(vip string, time time.Time) (float64, error) {
	pql := fmt.Sprintf(diskTotalPromQL, vip, vip)
	vds, err := c.Query(pql, time)
	if err != nil {
		return 0, fmt.Errorf("query(%s) failed %s", pql, err)
	}
	ret, err := parseData(vds)
	if err != nil {
		return 0, fmt.Errorf("parse query(%s) result, %s", pql, err)
	}
	return ret, nil
}

// DiskUsed 磁盘的使用大小(MB)
func (c *Client) DiskUsed(vip string, time time.Time) (float64, error) {
	pql := fmt.Sprintf(diskUsedPromQL, vip)
	vds, err := c.Query(pql, time)
	if err != nil {
		return 0, fmt.Errorf("query(%s) failed %s", pql, err)
	}
	ret, err := parseData(vds)
	if err != nil {
		return 0, fmt.Errorf("parse query(%s) result, %s", pql, err)
	}
	return ret, nil
}

// DiskFree 磁盘剩余空间大小(MB)
func (c *Client) DiskFree(vip string, time time.Time) (float64, error) {
	pql := fmt.Sprintf(diskFreePromQL, vip, vip, vip)
	vds, err := c.Query(pql, time)
	if err != nil {
		return 0, fmt.Errorf("query(%s) failed %s", pql, err)
	}

	ret, err := parseData(vds)
	if err != nil {
		return 0, fmt.Errorf("parse query(%s) result, %s", pql, err)
	}
	return ret, nil
}

func parseData(vds *VectorData) (float64, error) {
	var err error
	value := 0.0
	if len(vds.Result) == 0 {
		return value, NoDataPointError
	}

	for _, vd := range vds.Result {
		if len(vd.Value) >= 2 {
			if s, ok := vd.Value[1].(string); ok {
				value, err = strconv.ParseFloat(s, 64)
				if err != nil {
					return value, fmt.Errorf("ParseFloat parse metric.value to float64 failed, err:%s", err)
				}
			} else {
				return value, fmt.Errorf("convert interface to string failed, value:%v", vd.Value)
			}
		} else {
			return value, fmt.Errorf("metric.value length should > 2, value:%v", vd.Value)
		}
	}
	return value, nil
}
