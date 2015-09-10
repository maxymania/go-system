package posix_acl

import "syscall"
import "github.com/maxymania/go-system/syscall_x"

type AclType string

const ACL_ACCESS = AclType("system.posix_acl_access")
const ACL_DEFAULTS = AclType("system.posix_acl_default")

func (a *Acl)LoadF(fd int, t AclType) error {
	sz,err := syscall_x.Fgetxattr(fd,string(t),nil)
	if err!=nil { return err }
	buffer := make([]byte,sz)
	sz,err = syscall_x.Fgetxattr(fd,string(t),buffer)
	if err!=nil { return err }
	a.Decode(buffer[:sz])
	return nil
}
func (a *Acl)StoreF(fd int, t AclType) error {
	data := a.Encode()
	err := syscall_x.Fsetxattr(fd,string(t),data,0)
	return err
}
func (a *Acl)Load(fn string, t AclType) error {
	sz,err := syscall.Getxattr(fn,string(t),nil)
	if err!=nil { return err }
	buffer := make([]byte,sz)
	sz,err = syscall.Getxattr(fn,string(t),buffer)
	if err!=nil { return err }
	a.Decode(buffer[:sz])
	return nil
}
func (a *Acl)Store(fn string, t AclType) error {
	data := a.Encode()
	err := syscall.Setxattr(fn,string(t),data,0)
	return err
}


