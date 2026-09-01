function status(){return request({url:"/api/status",method:"get",timeout:2000})}
function list(params){return request({url:"/api/docker/containers",method:"get",params:{all:params.all,includeStats:params.stats}})}
function start(id){return request({url:`/api/docker/containers/${id}/start`,method:"post"})}
function update(key,data){return request({url:"/api/ddns/task/"+key,method:"put",data:data})}
function directDelete(base,id){return axios.delete(`${base}api/docker/images/${id}`)}
function upload(base,file){const form=new FormData();form.append("file",file);return axios.post(`${base}api/docker/images/upload-temp`,form,{headers:{"Content-Type":"multipart/form-data"}})}
function uploadBackup(base,value,form){return axios.post(`${base}api/docker/compose/${value}/backups/upload`,form,{headers:{"Content-Type":"multipart/form-data"}})}
const socketPath="/api/status/ws";
